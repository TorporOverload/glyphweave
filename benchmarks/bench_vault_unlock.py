"""Vault unlock: component breakdown + KDF cost sweep + first-file mount."""

from __future__ import annotations

import argparse
import secrets
import shutil
from pathlib import Path
from time import perf_counter

from app.common.paths.vault_layout import vault_key_path
from app.infrastructure.crypto.primitives.key_derivation import derive_kek_from_password
from app.infrastructure.crypto.service.key_service import KeyService
from app.infrastructure.crypto.service.utils import load_vault_key
from app.infrastructure.crypto.types import KDFParams
from app.services.vault_service import VaultService
from benchmarks import _harness as H

PASSWORD = "unlock-benchmark-pw"
MEMORY_GRID_MIB = [64, 128, 256, 512, 1024]
ITER_GRID = [1, 2, 3, 4, 5, 6]


def _build_vault(workdir: Path, kdf: KDFParams) -> Path:
    vault_path = workdir / "vault"
    if vault_path.exists():
        shutil.rmtree(vault_path)
    vault_path.mkdir(parents=True, exist_ok=True)
    svc = VaultService()
    svc.create_new_vault(vault_path, "unlock-bench", PASSWORD, kdf)
    svc.cleanup()
    return vault_path


def _measure_total_unlock(vault_path: Path) -> float:
    svc = VaultService()
    start = perf_counter()
    svc.prepare_existing_vault(vault_path)
    svc.open_existing_vault(PASSWORD)
    elapsed = perf_counter() - start
    svc.cleanup()
    return elapsed


def _measure_kdf_unwrap(vault_path: Path) -> float:
    ks = KeyService()
    ks.vault_key_file = load_vault_key(vault_key_path(vault_path))
    start = perf_counter()
    ks.unwrap_master_key(PASSWORD)
    return perf_counter() - start


def _measure_first_mount(vault_path: Path) -> float | None:
    svc = VaultService()
    try:
        svc.prepare_existing_vault(vault_path)
        svc.open_existing_vault(PASSWORD)
        src = vault_path.parent / "mountme.txt"
        src.write_text("first mount probe", encoding="utf-8")
        svc.add_file(src, dest_name="mountme.txt")
        ref = next(e for e in svc.list_root_entries() if not e.is_folder)
        mounts = svc.context.mounts
        start = perf_counter()
        info = mounts.mount_and_open(ref.id, open_in_app=False)
        elapsed = perf_counter() - start
        return None if info is None else elapsed
    except Exception:
        return None
    finally:
        svc.cleanup()


def run(
    workdir: Path,
    *,
    kdf: KDFParams = H.PROD_KDF,
    repeats: int = 5,
    sweep_repeats: int = 3,
    quick: bool = False,
) -> None:
    if quick:
        repeats, sweep_repeats = 2, 1
    workdir.mkdir(parents=True, exist_ok=True)
    vault_path = _build_vault(workdir, kdf)

    # (a) breakdown
    totals = [_measure_total_unlock(vault_path) for _ in range(repeats)]
    kdfs = [_measure_kdf_unwrap(vault_path) for _ in range(repeats)]
    total_s, kdf_s = H.summarize(totals), H.summarize(kdfs)
    rest_mean = max(0.0, total_s.mean - kdf_s.mean)
    rows = [
        {"component": "kdf_unwrap", "run_idx": i, "elapsed_s": v}
        for i, v in enumerate(kdfs)
    ] + [
        {"component": "total_unlock", "run_idx": i, "elapsed_s": v}
        for i, v in enumerate(totals)
    ]
    H.write_csv(
        H.RAW_DIR / "unlock_breakdown.csv", rows, ["component", "run_idx", "elapsed_s"]
    )

    # (b) KDF sweep
    mem_grid = MEMORY_GRID_MIB if not quick else [64, 256]
    iter_grid = ITER_GRID if not quick else [1, 2]
    sweep_rows = []
    for mib in mem_grid:
        params = KDFParams(memory_kb=mib * 1024, iterations=2)
        salt = secrets.token_bytes(params.salt_size)
        for i in range(sweep_repeats):
            start = perf_counter()
            derive_kek_from_password(PASSWORD, params, salt)
            sweep_rows.append(
                {
                    "param": "memory_mib",
                    "value": mib,
                    "run_idx": i,
                    "elapsed_s": perf_counter() - start,
                }
            )
    for iters in iter_grid:
        params = KDFParams(memory_kb=1024 * 1024, iterations=iters)
        salt = secrets.token_bytes(params.salt_size)
        for i in range(sweep_repeats):
            start = perf_counter()
            derive_kek_from_password(PASSWORD, params, salt)
            sweep_rows.append(
                {
                    "param": "iterations",
                    "value": iters,
                    "run_idx": i,
                    "elapsed_s": perf_counter() - start,
                }
            )
    H.write_csv(
        H.RAW_DIR / "unlock_kdf_sweep.csv",
        sweep_rows,
        ["param", "value", "run_idx", "elapsed_s"],
    )

    # (c) first-file mount (best-effort)
    mount = _measure_first_mount(vault_path)
    H.write_csv(
        H.RAW_DIR / "unlock_mount.csv",
        [{"run_idx": 0, "elapsed_s": "" if mount is None else mount}],
        ["run_idx", "elapsed_s"],
    )

    pct = f"{kdf_s.mean / total_s.mean * 100:.1f}% of unlock" if total_s.mean else "n/a"
    H.write_txt(
        H.RAW_DIR / "vault_unlock.txt",
        "Vault Unlock Benchmark",
        [
            (
                "End-to-end unlock",
                f"mean={total_s.mean:.3f}s median={total_s.median:.3f}s "
                f"stdev={total_s.stdev:.3f}s (n={total_s.n})",
            ),
            ("KDF + master-key unwrap", f"mean={kdf_s.mean:.3f}s ({pct})"),
            ("Bootstrap + DB open + I/O (derived)", f"mean={rest_mean:.3f}s"),
            (
                "First-file mount (cold)",
                f"{mount:.3f}s"
                if mount is not None
                else "unavailable (WinFsp not active)",
            ),
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="3. Vault unlock benchmark")
    parser.add_argument(
        "--workdir",
        type=Path,
        default=H.REPO_ROOT / "benchmarks" / ".vaults" / "unlock",
    )
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    run(args.workdir, quick=args.quick)
    from benchmarks.plotting import plot_vault_unlock

    plot_vault_unlock(H.RAW_DIR)


if __name__ == "__main__":
    main()
