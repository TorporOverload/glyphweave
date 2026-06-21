"""Search accuracy:
positive (P/R/MAP) and negative (specificity) tracks, with breakdowns."""

from __future__ import annotations

import argparse
import statistics as st
from pathlib import Path

from benchmarks import _corpus as C
from benchmarks import _harness as H
from benchmarks import _metrics as M

KS = [1, 5, 10, 20]
SCOPES = ("content", "filename", "both")


def _script(query: str) -> str:
    return "dhivehi" if C.is_dhivehi(query) else "latin"


def _avg_curve(curves: list[list[tuple[float, float]]]) -> list[tuple[float, float]]:
    if not curves:
        return []
    levels = [lvl for lvl, _ in curves[0]]
    return [(lvl, st.fmean(c[i][1] for c in curves)) for i, lvl in enumerate(levels)]


def run(
    corpus_dir: Path, labels_path: Path, workdir: Path, *, quick: bool = False
) -> None:
    labels = C.load_labels(labels_path)
    corpus = C.load_corpus(corpus_dir)
    if quick:
        corpus = corpus[:40]
        names = {p.name for p in corpus}
        labels = [lq for lq in labels if lq.is_negative or (lq.relevant & names)][:8]

    per_rows: list[dict] = []
    pos_curves: dict[str, list] = {"overall": [], "latin": [], "dhivehi": []}
    pos_ap: dict[str, list[float]] = {"overall": [], "latin": [], "dhivehi": []}
    pos_pk = {k: [] for k in KS}
    pos_rk = {k: [] for k in KS}
    aps: list[float] = []
    by_scope_ap: dict[str, list[float]] = {}
    by_scope_neg: dict[str, list[float]] = {}
    neg_zero: list[float] = []
    neg_spurious: list[int] = []

    with H.resumable_vault(workdir) as svc:
        existing = {e.file_name for e in svc.list_all_entries() if not e.is_folder}
        total = len(corpus)
        imported = len(existing)
        if imported:
            print(f"[accuracy build] resuming from {imported}/{total} already imported")
        for path in corpus:
            if path.name in existing:
                continue
            svc.add_file(path, dest_name=path.name)
            imported += 1
            if imported % 250 == 0:
                print(f"[accuracy build] imported {imported}/{total}")
        for lq in labels:
            page = svc.search_page(lq.query, limit=20, scope=lq.api_scope)
            retrieved = [r.file_name for r in page.results]
            relevant = set(lq.relevant)
            script = _script(lq.query)
            base = {
                "query": lq.query,
                "scope": lq.scope,
                "script": script,
                "is_negative": int(lq.is_negative),
                "num_relevant": len(relevant),
                "num_retrieved": len(retrieved),
                "num_rel_retrieved": sum(1 for d in retrieved if d in relevant),
            }
            if lq.is_negative:
                zero = len(retrieved) == 0
                neg_zero.append(1.0 if zero else 0.0)
                neg_spurious.append(len(retrieved))
                by_scope_neg.setdefault(lq.scope, []).append(1.0 if zero else 0.0)
                row = {**base, "average_precision": "", "returned_zero": int(zero)}
                for k in KS:
                    row[f"p_at_{k}"] = ""
                    row[f"r_at_{k}"] = ""
            else:
                ap = M.average_precision(retrieved, relevant)
                aps.append(ap)
                by_scope_ap.setdefault(lq.scope, []).append(ap)
                pos_ap["overall"].append(ap)
                pos_ap[script].append(ap)
                curve = M.interpolated_pr_curve(retrieved, relevant)
                pos_curves["overall"].append(curve)
                pos_curves[script].append(curve)
                row = {**base, "average_precision": ap, "returned_zero": ""}
                for k in KS:
                    p = M.precision_at_k(retrieved, relevant, k)
                    r = M.recall_at_k(retrieved, relevant, k)
                    pos_pk[k].append(p)
                    pos_rk[k].append(r)
                    row[f"p_at_{k}"] = p
                    row[f"r_at_{k}"] = r
            per_rows.append(row)

    fields = (
        [
            "query",
            "scope",
            "script",
            "is_negative",
            "num_relevant",
            "num_retrieved",
            "num_rel_retrieved",
        ]
        + [f"p_at_{k}" for k in KS]
        + [f"r_at_{k}" for k in KS]
        + ["average_precision", "returned_zero"]
    )
    H.write_csv(H.RAW_DIR / "accuracy_per_query.csv", per_rows, fields)

    curve_rows = [
        {"group": g, "recall_level": lvl, "precision": prec}
        for g, curves in pos_curves.items()
        for lvl, prec in _avg_curve(curves)
    ]
    H.write_csv(
        H.RAW_DIR / "accuracy_pr_curve.csv",
        curve_rows,
        ["group", "recall_level", "precision"],
    )

    # mean AP per script group — annotates the scikit-learn PR display
    ap_rows = [
        {"group": g, "average_precision": st.fmean(v)} for g, v in pos_ap.items() if v
    ]
    H.write_csv(H.RAW_DIR / "accuracy_ap.csv", ap_rows, ["group", "average_precision"])

    atk_rows = [
        {
            "k": k,
            "mean_precision": st.fmean(pos_pk[k]) if pos_pk[k] else 0.0,
            "mean_recall": st.fmean(pos_rk[k]) if pos_rk[k] else 0.0,
            "f1": M.f1(
                st.fmean(pos_pk[k]) if pos_pk[k] else 0.0,
                st.fmean(pos_rk[k]) if pos_rk[k] else 0.0,
            ),
        }
        for k in KS
    ]
    H.write_csv(
        H.RAW_DIR / "accuracy_at_k.csv",
        atk_rows,
        ["k", "mean_precision", "mean_recall", "f1"],
    )

    scope_rows = [
        {
            "scope": s,
            "map": st.fmean(by_scope_ap[s]) if by_scope_ap.get(s) else 0.0,
            "specificity": st.fmean(by_scope_neg[s]) if by_scope_neg.get(s) else 0.0,
        }
        for s in SCOPES
    ]
    H.write_csv(
        H.RAW_DIR / "accuracy_by_scope.csv", scope_rows, ["scope", "map", "specificity"]
    )

    mapv = st.fmean(aps) if aps else 0.0
    spec = st.fmean(neg_zero) if neg_zero else 0.0
    H.write_txt(
        H.RAW_DIR / "search_accuracy.txt",
        "Search Accuracy Benchmark",
        [
            (
                "Positive queries",
                f"n={len(aps)} MAP={mapv:.3f} "
                f"meanP@10={st.fmean(pos_pk[10]) if pos_pk[10] else 0:.3f} "
                f"meanR@10={st.fmean(pos_rk[10]) if pos_rk[10] else 0:.3f}",
            ),
            (
                "Negative queries",
                f"n={len(neg_zero)} specificity(zero-result)={spec:.3f} "
                f"mean_spurious_hits={st.fmean(neg_spurious) if neg_spurious else 0:.2f}",
            ),
            (
                "By scope (MAP / specificity)",
                "\n".join(
                    f"  {r['scope']}: MAP={r['map']:.3f} specificity={r['specificity']:.3f}"
                    for r in scope_rows
                ),
            ),
        ],
    )


def main() -> None:
    base = H.REPO_ROOT / "test_data" / "search accuracy"
    parser = argparse.ArgumentParser(description="5. Search accuracy benchmark")
    parser.add_argument("--corpus", type=Path, default=base / "search_test_corpus")
    parser.add_argument("--labels", type=Path, default=base / "labels.json")
    parser.add_argument(
        "--workdir",
        type=Path,
        default=H.REPO_ROOT / "benchmarks" / ".vaults" / "accuracy",
    )
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    run(args.corpus, args.labels, args.workdir, quick=args.quick)
    from benchmarks.plotting import plot_search_accuracy

    plot_search_accuracy(H.RAW_DIR)


if __name__ == "__main__":
    main()
