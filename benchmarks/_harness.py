from __future__ import annotations

import csv
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Generator, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "benchmarks" / "results"
RAW_DIR = RESULTS_DIR / "raw"
FIG_DIR = RESULTS_DIR / "figures"


@dataclass(frozen=True)
class Stats:
    n: int
    mean: float
    median: float
    stdev: float
    min: float
    max: float
    p95: float


def _percentile(samples: Sequence[float], pct: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    if len(ordered) == 1:
        return ordered[0]
    rank = (pct / 100.0) * (len(ordered) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(ordered) - 1)
    frac = rank - lo
    return ordered[lo] + (ordered[hi] - ordered[lo]) * frac


def summarize(samples: Sequence[float]) -> Stats:
    vals = list(samples)
    if not vals:
        return Stats(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    return Stats(
        n=len(vals),
        mean=statistics.fmean(vals),
        median=statistics.median(vals),
        stdev=statistics.stdev(vals) if len(vals) > 1 else 0.0,
        min=min(vals),
        max=max(vals),
        p95=_percentile(vals, 95.0),
    )


def measure(fn: Callable[[], object], *, repeats: int, warmup: int = 0) -> list[float]:
    """Call fn (warmup + repeats) times;
    return perf_counter elapsed seconds for the repeats only."""
    for _ in range(warmup):
        fn()
    samples: list[float] = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return samples


def write_csv(path: Path, rows: Sequence[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_txt(path: Path, title: str, sections: Sequence[tuple[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [title, "=" * len(title), ""]
    for heading, body in sections:
        lines += [heading, "-" * len(heading), body.rstrip(), ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO_ROOT,
            text=True,  # noqa
        ).strip()
    except Exception:
        return "unknown"


def capture_meta(extra: dict | None = None) -> dict:
    import importlib.metadata as md

    def _ver(name: str) -> str:
        try:
            return md.version(name)
        except Exception:
            return "absent"

    meta = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "git_sha": _git_sha(),
        "packages": {
            name: _ver(name)
            for name in ("matplotlib", "scienceplots", "numpy", "cryptography")
        },
    }
    if extra:
        meta.update(extra)
    return meta


def write_meta(extra: dict | None = None) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / "meta.json"
    path.write_text(json.dumps(capture_meta(extra), indent=2), encoding="utf-8")
    return path


def free_disk_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free


# Cheap KDF for vaults whose unlock time we are NOT measuring.
from app.common.paths.vault_layout import vault_key_path  # noqa: E402
from app.infrastructure.crypto.types import KDFParams  # noqa: E402
from app.services.vault_service import VaultService  # noqa: E402

FAST_KDF = KDFParams(memory_kb=8 * 1024, iterations=1, parallelism=1)
# Shipped production defaults (1 GiB / 2 / 8) — used only by the unlock benchmark.
PROD_KDF = KDFParams()


@contextmanager
def temp_vault(
    workdir: Path,
    *,
    kdf: KDFParams = FAST_KDF,
    password: str = "benchmark-pw",  # noqa
    name: str = "bench",
) -> "Generator[VaultService]":
    """Create a throwaway vault under workdir,
        yield an opened VaultService, always clean up.
    Any pre-existing vault at ``workdir/vault`` is removed first so the benchmark
    is re-runnable (``create_new_vault`` refuses to overwrite an existing vault).
    """
    vault_path = workdir / "vault"
    if vault_path.exists():
        shutil.rmtree(vault_path, ignore_errors=True)
    vault_path.mkdir(parents=True, exist_ok=True)
    service = VaultService()
    try:
        service.create_new_vault(vault_path, name, password, kdf)
        try:
            service.list_root_entries()  # already open?
        except Exception:
            service.prepare_existing_vault(vault_path)
            service.open_existing_vault(password)
        yield service
    finally:
        try:
            service.cleanup()
        except Exception:
            pass


@contextmanager
def resumable_vault(
    workdir: Path,
    *,
    kdf: KDFParams = FAST_KDF,
    password: str = "benchmark-pw",
    name: str = "bench",
) -> "Generator[VaultService]":
    """Open a persistent vault under workdir/vault, creating it if it doesn't exist.

    Unlike temp_vault, never wipes an existing vault so interrupted runs can be
    resumed by re-running the benchmark without re-importing files from scratch.
    """
    vault_path = workdir / "vault"
    vault_path.mkdir(parents=True, exist_ok=True)
    service = VaultService()
    try:
        if vault_key_path(vault_path).exists():
            service.prepare_existing_vault(vault_path)
            service.open_existing_vault(password)
        else:
            service.create_new_vault(vault_path, name, password, kdf)
            try:
                service.list_root_entries()
            except Exception:
                service.prepare_existing_vault(vault_path)
                service.open_existing_vault(password)
        yield service
    finally:
        try:
            service.cleanup()
        except Exception:
            pass


def mount_and_wait(
    service: "VaultService", ref_id: int, *, timeout: float = 15.0
) -> Path:
    """Mount a vault file and block until the mounted path is actually readable.

    WinFsp mounts asynchronously: ``mount_and_open`` returns before the mount
    point is visible/responsive, so callers must wait before opening the file
    (mirrors the probe logic in ``tools/single_fs_mount_capacity.py``).
    Returns the mounted file path; raises RuntimeError on failure/timeout.
    """
    mounts = service.context.mounts
    if mounts is None:
        raise RuntimeError("mount orchestrator is not initialized")
    info = mounts.mount_and_open(ref_id, open_in_app=False)
    if info is None:
        raise RuntimeError("mount_and_open returned None")
    path = Path(info.file_path)
    if not mounts._wait_for_mount_responsive(path, timeout):
        raise RuntimeError(f"mount not responsive within {timeout}s: {path}")
    return path
