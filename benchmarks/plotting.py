from __future__ import annotations

import csv
from pathlib import Path

import matplotlib
import numpy as np

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

import scienceplots  # noqa: F401,E402  (registers the 'science' style)
from benchmarks._harness import FIG_DIR  # noqa: E402

_STYLE_READY = False
PALETTE = ["#0C5DA5", "#FF2C00", "#00B945", "#845B97", "#FF9500", "#474747"]


def setup_style() -> None:
    global _STYLE_READY
    if _STYLE_READY:
        return
    plt.style.use(["science", "no-latex"])
    matplotlib.rcParams.update(
        {
            "text.usetex": False,
            "figure.dpi": 300,
            "savefig.dpi": 300,
            "figure.figsize": (5.0, 3.5),
            "axes.prop_cycle": plt.cycler(color=PALETTE),
            "legend.frameon": True,
        }
    )
    _STYLE_READY = True


def save(fig, name: str) -> tuple[Path, Path]:
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    pdf = FIG_DIR / f"{name}.pdf"
    png = FIG_DIR / f"{name}.png"
    fig.savefig(pdf, bbox_inches="tight")
    fig.savefig(png, bbox_inches="tight")
    plt.close(fig)
    return pdf, png


def plot_vault_unlock(raw_dir: Path, name: str = "vault_unlock"):
    setup_style()
    comp: dict[str, list[float]] = {}
    with (raw_dir / "unlock_breakdown.csv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            comp.setdefault(row["component"], []).append(float(row["elapsed_s"]))
    total = float(np.mean(comp.get("total_unlock", [0.0])))
    kdf = float(np.mean(comp.get("kdf_unwrap", [0.0])))
    rest = max(0.0, total - kdf)

    agg: dict[tuple[str, float], list[float]] = {}
    with (raw_dir / "unlock_kdf_sweep.csv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            agg.setdefault((row["param"], float(row["value"])), []).append(
                float(row["elapsed_s"])
            )
    mem = sorted(
        (v, float(np.mean(s))) for (p, v), s in agg.items() if p == "memory_mib"
    )
    it = sorted(
        (v, float(np.mean(s))) for (p, v), s in agg.items() if p == "iterations"
    )

    fig, (axb, axm, axi) = plt.subplots(1, 3, figsize=(9.5, 3.2))
    axb.bar(["unlock"], [kdf], label="KDF + unwrap", color=PALETTE[0])
    axb.bar(
        ["unlock"], [rest], bottom=[kdf], label="bootstrap + DB + I/O", color=PALETTE[2]
    )
    axb.set_ylabel("Time (s)")
    axb.set_title("Unlock breakdown")
    axb.legend(fontsize=7)
    if mem:
        axm.plot([m[0] for m in mem], [m[1] for m in mem], "o-")
    axm.set_xlabel("Argon2id memory (MiB)")
    axm.set_ylabel("KDF time (s)")
    axm.set_title("KDF vs memory")
    if it:
        axi.plot([m[0] for m in it], [m[1] for m in it], "s-", color=PALETTE[1])
    axi.set_xlabel("Argon2id iterations")
    axi.set_ylabel("KDF time (s)")
    axi.set_title("KDF vs iterations")
    axb.grid(True, axis="y", alpha=0.3)
    axm.grid(True, alpha=0.3)
    axi.grid(True, alpha=0.3)
    fig.tight_layout()
    return save(fig, name)


def plot_fuse_throughput(raw_dir: Path, name: str = "fuse_throughput"):
    setup_style()
    series: dict[tuple[str, str], list[tuple[int, float]]] = {}
    with (raw_dir / "fuse_throughput.csv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row["status"] != "ok":
                continue
            key = (row["layer"], row["op"])
            series.setdefault(key, []).append(
                (int(row["file_size_bytes"]), float(row["throughput_mbps"]))
            )

    fig, ax = plt.subplots()
    markers = {"in_process": "o", "real_mount": "s"}
    for (layer, op), pts in sorted(series.items()):
        pts.sort()
        xs = [p[0] / (1 << 20) for p in pts]
        ys = [p[1] for p in pts]
        ax.plot(xs, ys, marker=markers.get(layer, "o"), label=f"{layer} {op}")
    ax.set_xscale("log")
    ax.set_xlabel("File size (MiB)")
    ax.set_ylabel("Throughput (MB/s)")
    ax.set_title("FUSE I/O throughput")
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=7)
    fig.tight_layout()
    return save(fig, name)


def plot_search_latency(raw_dir: Path, name: str = "search_latency"):
    setup_style()
    by_type: dict[str, dict[int, list[float]]] = {}
    with (raw_dir / "search_latency.csv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            by_type.setdefault(row["query_type"], {}).setdefault(
                int(row["corpus_size"]), []
            ).append(float(row["latency_ms"]))

    SLOW_THRESHOLD_MS = 10.0
    slow = {
        qt: ps
        for qt, ps in by_type.items()
        if float(np.median(list(ps.values())[0])) >= SLOW_THRESHOLD_MS
    }
    fast = {qt: ps for qt, ps in by_type.items() if qt not in slow}

    def _draw(ax, subset, title):
        for qtype, per_size in sorted(subset.items()):
            sizes = sorted(per_size)
            med = [float(np.median(per_size[s])) for s in sizes]
            lo = [float(np.percentile(per_size[s], 5)) for s in sizes]
            hi = [float(np.percentile(per_size[s], 95)) for s in sizes]
            (line,) = ax.plot(sizes, med, marker="o", label=qtype)
            ax.fill_between(sizes, lo, hi, alpha=0.15, color=line.get_color())
        ax.set_xscale("log")
        ax.set_xlabel("Corpus size (documents)")
        ax.set_ylabel("Search latency (ms)")
        ax.set_title(title)
        ax.grid(True, alpha=0.3)
        ax.legend(fontsize=7)

    if slow and fast:
        fig, (ax_slow, ax_fast) = plt.subplots(1, 2, figsize=(11, 4))
        _draw(ax_slow, slow, "Search latency — result-returning queries")
        _draw(ax_fast, fast, "Search latency — zero-result queries")
    else:
        fig, ax = plt.subplots()
        _draw(ax, by_type, "Search latency vs corpus size")
    fig.tight_layout()
    return save(fig, name)


def plot_db_size(raw_dir: Path, name: str = "db_size"):
    setup_style()
    with (raw_dir / "db_size.csv").open(encoding="utf-8") as fh:
        rows = sorted(csv.DictReader(fh), key=lambda r: int(r["corpus_size"]))
    mib = 1 << 20
    docs = [int(r["corpus_size"]) for r in rows]
    corpus = [int(r["corpus_bytes"]) / mib for r in rows]
    db = [int(r["db_bytes"]) / mib for r in rows]
    vault = [int(r["vault_bytes"]) / mib for r in rows]
    components = [
        ("blobs", [int(r["blob_bytes"]) / mib for r in rows], PALETTE[0]),
        ("DB snapshot", [int(r["db_dumps_bytes"]) / mib for r in rows], PALETTE[1]),
        ("events", [int(r["events_bytes"]) / mib for r in rows], PALETTE[2]),
        ("key/metadata", [int(r["other_bytes"]) / mib for r in rows], PALETTE[3]),
    ]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.5, 3.4))
    # left: what the vault is made of, stacked to the vault total at each size
    x = np.arange(len(docs))
    bottom = np.zeros(len(docs))
    for label, vals, color in components:
        ax1.bar(x, vals, bottom=bottom, label=label, color=color, width=0.6)
        bottom += np.array(vals)
    ax1.plot(x, corpus, "k--o", lw=1, ms=3, label="raw corpus")
    ax1.set_xticks(x)
    ax1.set_xticklabels(docs)
    ax1.set_xlabel("Corpus size (documents)")
    ax1.set_ylabel("On-disk size (MiB)")
    ax1.set_title("Vault composition vs corpus")
    ax1.grid(True, axis="y", alpha=0.3)
    ax1.legend(fontsize=6)

    # right: storage overhead relative to the raw corpus bytes
    ratio_vault = [v / c if c else 0.0 for v, c in zip(vault, corpus)]
    ratio_db = [d / c if c else 0.0 for d, c in zip(db, corpus)]
    ax2.plot(docs, ratio_vault, marker="o", label="vault / corpus")
    ax2.plot(docs, ratio_db, marker="s", label="working DB / corpus")
    ax2.axhline(1.0, ls="--", color=PALETTE[5], alpha=0.6)
    ax2.set_xscale("log")
    ax2.set_xlabel("Corpus size (documents)")
    ax2.set_ylabel("Storage ratio (×)")
    ax2.set_title("Storage overhead")
    ax2.grid(True, alpha=0.3)
    ax2.legend(fontsize=7)
    fig.tight_layout()
    return save(fig, name)


def plot_concurrent_access(raw_dir: Path, name: str = "concurrent_access"):
    setup_style()
    conc, success_rate, latency = [], [], []
    with (raw_dir / "concurrent_access.csv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            t = int(row["concurrency"])
            total = int(row["total_ops"]) or 1
            conc.append(t)
            success_rate.append(100.0 * int(row["successes"]) / total)
            latency.append(float(row["mean_latency_ms"]))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8.0, 3.2))
    ax1.plot(conc, success_rate, marker="o", color=PALETTE[2])
    ax1.set_xscale("log", base=2)
    ax1.set_ylim(0, 105)
    ax1.set_xlabel("Concurrency (threads)")
    ax1.set_ylabel("Success rate (%)")
    ax1.set_title("Correctness under load")
    ax2.plot(conc, latency, marker="s", color=PALETTE[0])
    ax2.set_xscale("log", base=2)
    ax2.set_xlabel("Concurrency (threads)")
    ax2.set_ylabel("Mean op latency (ms)")
    ax2.set_title("Latency under load")
    ax1.grid(True, alpha=0.3)
    ax2.grid(True, alpha=0.3)
    fig.tight_layout()
    return save(fig, name)


def plot_search_accuracy(raw_dir: Path, name: str = "accuracy"):
    from sklearn.metrics import PrecisionRecallDisplay

    setup_style()

    # 1) PR curve (overall + per script), rendered with scikit-learn's display
    groups: dict[str, list[tuple[float, float]]] = {}
    with (raw_dir / "accuracy_pr_curve.csv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            groups.setdefault(row["group"], []).append(
                (float(row["recall_level"]), float(row["precision"]))
            )
    ap_by_group: dict[str, float] = {}
    ap_path = raw_dir / "accuracy_ap.csv"
    if ap_path.exists():
        with ap_path.open(encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                ap_by_group[row["group"]] = float(row["average_precision"])
    fig, ax = plt.subplots()
    for i, (g, pts) in enumerate(sorted(groups.items())):
        pts.sort()
        # sklearn 1.9's multi-curve API needs ndarrays (a flat list reads as
        # one curve per point) and per-curve style via curve_kwargs.
        PrecisionRecallDisplay(
            precision=np.array([p[1] for p in pts]),
            recall=np.array([p[0] for p in pts]),
            average_precision=ap_by_group.get(g),
        ).plot(
            ax=ax,
            name=g,
            curve_kwargs={"marker": "o", "color": PALETTE[i % len(PALETTE)]},
        )
    ax.set_ylim(0, 1.05)
    ax.grid(True, alpha=0.3)
    ax.set_title("Precision–Recall (interpolated)")
    ax.legend(fontsize=7)
    fig.tight_layout()
    save(fig, "accuracy_pr_curve")

    # 2) P/R/F1 at k
    ks, p, r, f = [], [], [], []
    with (raw_dir / "accuracy_at_k.csv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            ks.append(int(row["k"]))
            p.append(float(row["mean_precision"]))
            r.append(float(row["mean_recall"]))
            f.append(float(row["f1"]))
    x = np.arange(len(ks))
    w = 0.25
    fig2, ax2 = plt.subplots()
    ax2.bar(x - w, p, w, label="P@k")
    ax2.bar(x, r, w, label="R@k")
    ax2.bar(x + w, f, w, label="F1@k")
    ax2.set_xticks(x)
    ax2.set_xticklabels([f"k={k}" for k in ks])
    ax2.set_ylabel("Score")
    ax2.set_ylim(0, 1.05)
    ax2.set_title("Precision/Recall/F1 at k")
    ax2.grid(True, axis="y", alpha=0.3)
    ax2.legend(fontsize=7)
    fig2.tight_layout()
    save(fig2, "accuracy_at_k")

    # 3) by scope: MAP vs specificity
    sc, mp, sp = [], [], []
    with (raw_dir / "accuracy_by_scope.csv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            sc.append(row["scope"])
            mp.append(float(row["map"]))
            sp.append(float(row["specificity"]))
    x = np.arange(len(sc))
    w = 0.35
    fig3, ax3 = plt.subplots()
    ax3.bar(x - w / 2, mp, w, label="MAP (positive)")
    ax3.bar(x + w / 2, sp, w, label="Specificity (negative)")
    ax3.set_xticks(x)
    ax3.set_xticklabels(sc)
    ax3.set_ylim(0, 1.05)
    ax3.set_title("Accuracy by scope")
    ax3.grid(True, axis="y", alpha=0.3)
    ax3.legend(fontsize=7)
    fig3.tight_layout()
    return save(fig3, "accuracy_by_scope")
