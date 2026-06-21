from __future__ import annotations

import argparse
from pathlib import Path

from benchmarks import _harness as H

ALL = ["fuse", "search", "unlock", "concurrent", "accuracy", "storage"]


def main() -> None:
    base = H.REPO_ROOT / "benchmarks" / ".vaults"
    acc = H.REPO_ROOT / "test_data" / "search accuracy"
    parser = argparse.ArgumentParser(description="GlyphWeave benchmark runner")
    parser.add_argument(
        "--only",
        default=",".join(ALL),
        help="comma list: fuse,search,unlock,concurrent,accuracy,storage",
    )
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--no-plots", action="store_true")
    parser.add_argument(
        "--latency-corpus",
        type=Path,
        default=acc / "search_test_corpus",
        help="corpus; for the 10k run pass path/to/corpus-large",
    )
    parser.add_argument(
        "--accuracy-corpus", type=Path, default=acc / "search_test_corpus"
    )
    parser.add_argument(
        "--storage-corpus", type=Path, default=acc / "search_test_corpus"
    )
    parser.add_argument("--labels", type=Path, default=acc / "labels.json")
    args = parser.parse_args()
    selected = [s.strip() for s in args.only.split(",") if s.strip()]

    H.write_meta({"selected": selected, "quick": args.quick})

    if "unlock" in selected:
        from benchmarks import bench_vault_unlock as B

        B.run(base / "unlock", quick=args.quick)
        if not args.no_plots:
            from benchmarks.plotting import plot_vault_unlock

            plot_vault_unlock(H.RAW_DIR)

    if "fuse" in selected:
        from benchmarks import bench_fuse_throughput as B

        B.run(base / "fuse", quick=args.quick)
        if not args.no_plots:
            from benchmarks.plotting import plot_fuse_throughput

            plot_fuse_throughput(H.RAW_DIR)

    if "search" in selected:
        from benchmarks import bench_search_latency as B

        B.run(
            args.latency_corpus,
            base / "latency",
            labels_path=args.labels,
            quick=args.quick,
        )
        if not args.no_plots:
            from benchmarks.plotting import plot_search_latency

            plot_search_latency(H.RAW_DIR)

    if "concurrent" in selected:
        from benchmarks import bench_concurrent_access as B

        B.run(base / "concurrent", quick=args.quick)
        if not args.no_plots:
            from benchmarks.plotting import plot_concurrent_access

            plot_concurrent_access(H.RAW_DIR)

    if "accuracy" in selected:
        from benchmarks import bench_search_accuracy as B

        B.run(args.accuracy_corpus, args.labels, base / "accuracy", quick=args.quick)
        if not args.no_plots:
            from benchmarks.plotting import plot_search_accuracy

            plot_search_accuracy(H.RAW_DIR)

    if "storage" in selected:
        from benchmarks import bench_db_size as B

        B.run(args.storage_corpus, base / "storage", quick=args.quick)
        if not args.no_plots:
            from benchmarks.plotting import plot_db_size

            plot_db_size(H.RAW_DIR)

    print(f"Done. Raw -> {H.RAW_DIR}  Figures -> {H.FIG_DIR}")


if __name__ == "__main__":
    main()
