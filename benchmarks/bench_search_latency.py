"""Search latency vs corpus size:
real add_file build into a persisted, resumable vault."""

from __future__ import annotations

import argparse
from pathlib import Path
from time import perf_counter

from benchmarks import _corpus as C
from benchmarks import _harness as H

PASSWORD = "latency-bench-pw"
RUNS_PER_QUERY = 20
# (query, query_type, scope):
# scope is the search_page vocabulary (all/filename/content)
DEFAULT_QUERIES = [
    ("data", "single_term", "content"),
    ("annual report", "phrase", "content"),
    ("000", "filename_prefix", "filename"),
    ("ދިވެހި", "dhivehi", "content"),
]


def negative_queries(labels_path: Path) -> list[tuple[str, str, str]]:
    """Borrow zero-relevance queries from the accuracy labels, tagged by shape.

    Scope is mapped to the search_page vocabulary via LabeledQuery.api_scope
    (both -> all). These are *candidate* misses: whether a borrowed query is
    actually empty on a given corpus is re-verified at run time, not assumed.
    """
    out: list[tuple[str, str, str]] = []
    for lq in C.load_labels(labels_path):
        if not lq.is_negative:
            continue
        if C.is_dhivehi(lq.query):
            qtype = "negative_dhivehi"
        elif " " in lq.query.strip():
            qtype = "negative_phrase"
        else:
            qtype = "negative_term"
        out.append((lq.query, qtype, lq.api_scope))
    return out


def run(
    corpus_dir: Path,
    workdir: Path,
    *,
    sizes: list[int] | None = None,
    queries=DEFAULT_QUERIES,
    labels_path: Path | None = None,
    runs: int = RUNS_PER_QUERY,
    quick: bool = False,
) -> None:
    corpus = C.seeded_order(C.load_corpus(corpus_dir))
    if not corpus:
        raise SystemExit(f"No supported documents under {corpus_dir}")
    negatives = (
        negative_queries(labels_path) if labels_path and labels_path.exists() else []
    )
    if quick:
        corpus = corpus[:8]
        sizes = [4, 8]
        runs = 3
        negatives = negatives[:4]
    sizes = sizes or C.default_sizes(len(corpus))
    batches = C.size_batches(corpus, sizes)

    rows: list[dict] = []
    with H.resumable_vault(workdir, password=PASSWORD) as svc:
        imported = sum(1 for e in svc.list_all_entries() if not e.is_folder)
        for size, _subset in batches:
            imported = C.import_documents(
                svc, corpus, imported, size, label="search-latency", total=sizes[-1]
            )
            # Positives are timed as-is. Borrowed negatives are probed once and
            # only kept where they genuinely return nothing on this corpus —
            # a "miss" that happens to hit at this size is dropped, not timed.
            active = list(queries)
            for nq, nqtype, nscope in negatives:
                if svc.search_page(nq, limit=20, scope=nscope).results:
                    print(
                        f"[search-latency] drop negative {nq!r} at size={size}: returned hits"
                    )
                    continue
                active.append((nq, nqtype, nscope))
            for query, qtype, scope in active:
                for run_idx in range(runs):
                    start = perf_counter()
                    page = svc.search_page(query, limit=20, scope=scope)
                    latency_ms = (perf_counter() - start) * 1000.0
                    rows.append(
                        {
                            "corpus_size": size,
                            "query": query,
                            "query_type": qtype,
                            "run_idx": run_idx,
                            "latency_ms": latency_ms,
                            "result_count": len(page.results),
                        }
                    )
            print(f"[search-latency measure] size={size} done")

    H.write_csv(
        H.RAW_DIR / "search_latency.csv",
        rows,
        ["corpus_size", "query", "query_type", "run_idx", "latency_ms", "result_count"],
    )

    # summary: per (size, query_type) median/p95
    groups: dict[tuple[int, str], list[float]] = {}
    for r in rows:
        groups.setdefault((r["corpus_size"], r["query_type"]), []).append(
            r["latency_ms"]
        )
    sections = []
    for (size, qtype), lat in sorted(groups.items()):
        s = H.summarize(lat)
        sections.append(
            (
                f"size={size} {qtype}",
                f"median={s.median:.2f}ms p95={s.p95:.2f}ms mean={s.mean:.2f}ms (n={s.n})",
            )
        )
    H.write_txt(
        H.RAW_DIR / "search_latency.txt", "Search Latency vs Corpus Size", sections
    )


def main() -> None:
    base = H.REPO_ROOT / "test_data" / "search accuracy"
    parser = argparse.ArgumentParser(description="2. Search latency benchmark")
    parser.add_argument("--corpus", type=Path, default=base / "search_test_corpus")
    parser.add_argument(
        "--labels",
        type=Path,
        default=base / "labels.json",
        help="accuracy labels file to borrow zero-result (miss) queries from",
    )
    parser.add_argument(
        "--workdir",
        type=Path,
        default=H.REPO_ROOT / "benchmarks" / ".vaults" / "latency",
    )
    parser.add_argument("--sizes", type=int, nargs="*", default=None)
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    run(
        args.corpus,
        args.workdir,
        sizes=args.sizes,
        labels_path=args.labels,
        quick=args.quick,
    )
    from benchmarks.plotting import plot_search_latency

    plot_search_latency(H.RAW_DIR)


if __name__ == "__main__":
    main()
