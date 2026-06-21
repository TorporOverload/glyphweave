"""Concurrent file access:
    escalate concurrency until a correctness failure."""

from __future__ import annotations

import argparse
import os
import secrets
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import perf_counter

from benchmarks import _harness as H

PAYLOAD = 64 * 1024
LADDER = [1, 2, 4, 8, 16, 32, 64, 128, 256]


def _worker(svc, ref_id: int) -> tuple[str, float]:
    mounts = svc.context.mounts
    start = perf_counter()
    try:
        path = H.mount_and_wait(svc, ref_id)
        payload = secrets.token_bytes(PAYLOAD)
        with path.open("r+b") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        with path.open("rb") as fh:
            read_back = fh.read(len(payload))
        status = "ok" if read_back == payload else "integrity"
        return status, perf_counter() - start
    except Exception:
        return "exception", perf_counter() - start
    finally:
        try:
            mounts.unmount(ref_id)
        except Exception:
            pass


def run(workdir: Path, *, cap: int = 256, quick: bool = False) -> None:
    workdir.mkdir(parents=True, exist_ok=True)
    if quick:
        cap = 4
    ladder = [t for t in LADDER if t <= cap]

    rows: list[dict] = []
    with H.resumable_vault(workdir) as svc:
        existing = sum(1 for e in svc.list_all_entries() if not e.is_folder)
        if existing:
            print(f"[concurrent] resuming vault with {existing} existing files")
        for i in range(existing, cap):
            src = workdir / f"src_{i}.bin"
            src.write_bytes(secrets.token_bytes(PAYLOAD))
            svc.add_file(src, dest_name=f"conc_{i:04d}.bin")
        ref_ids = [e.id for e in svc.list_all_entries() if not e.is_folder]

        stopped = "completed_ladder"
        for t in ladder:
            if t > len(ref_ids):
                stopped = "out_of_files"
                break
            targets = ref_ids[:t]
            with ThreadPoolExecutor(max_workers=t) as pool:
                results = list(pool.map(lambda r: _worker(svc, r), targets))
            statuses = [s for s, _ in results]
            lats = [d * 1000.0 for _, d in results]
            successes = sum(1 for s in statuses if s == "ok")
            integrity = sum(1 for s in statuses if s == "integrity")
            failures = sum(1 for s in statuses if s in ("fail_mount", "exception"))
            rows.append(
                {
                    "concurrency": t,
                    "total_ops": t,
                    "successes": successes,
                    "failures": failures,
                    "integrity_failures": integrity,
                    "mean_latency_ms": sum(lats) / len(lats) if lats else 0.0,
                    "throughput_mbps": (t * PAYLOAD / (1024 * 1024))
                    / (max(lats) / 1000.0)
                    if lats and max(lats) > 0
                    else 0.0,
                    "stopped_reason": "",
                }
            )
            print(
                f"[concurrent] T={t} ok={successes} integrity={integrity} fail={failures}"
            )
            if integrity or failures:
                stopped = f"correctness_break_at_T={t}"
                break
        if rows:
            rows[-1]["stopped_reason"] = stopped

    H.write_csv(
        H.RAW_DIR / "concurrent_access.csv",
        rows,
        [
            "concurrency",
            "total_ops",
            "successes",
            "failures",
            "integrity_failures",
            "mean_latency_ms",
            "throughput_mbps",
            "stopped_reason",
        ],
    )

    clean = [r for r in rows if r["failures"] == 0 and r["integrity_failures"] == 0]
    max_ok = max((r["concurrency"] for r in clean), default=0)
    H.write_txt(
        H.RAW_DIR / "concurrent_access.txt",
        "Concurrent File Access Benchmark",
        [
            ("Max concurrency at 100% correctness", str(max_ok)),
            ("Stop reason", rows[-1]["stopped_reason"] if rows else "no runs"),
            ("Levels tested", ", ".join(str(r["concurrency"]) for r in rows)),
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="4. Concurrent access benchmark")
    parser.add_argument(
        "--workdir",
        type=Path,
        default=H.REPO_ROOT / "benchmarks" / ".vaults" / "concurrent",
    )
    parser.add_argument("--cap", type=int, default=256)
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    run(args.workdir, cap=args.cap, quick=args.quick)
    from benchmarks.plotting import plot_concurrent_access

    plot_concurrent_access(H.RAW_DIR)


if __name__ == "__main__":
    main()
