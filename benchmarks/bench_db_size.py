"""Storage footprint vs corpus size:
how the encrypted DB and vault grow."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from app.common.paths import vault_layout as VL
from benchmarks import _corpus as C
from benchmarks import _harness as H


def _dir_bytes(path: Path) -> int:
    return (
        sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
        if path.exists()
        else 0
    )


def _db_bytes(svc) -> int:
    """Live SQLCipher database size on disk, including any -wal/-shm sidecars.

    The working DB lives outside the vault dir (``vaults_data_dir/<id>/vault.db``),
    so it is reached through the service context rather than by globbing the vault.
    """
    db_path = Path(svc.context.db.db_path)
    return sum(
        f.stat().st_size for f in db_path.parent.glob(db_path.name + "*") if f.is_file()
    )


def run(
    corpus_dir: Path,
    workdir: Path,
    *,
    sizes: list[int] | None = None,
    quick: bool = False,
) -> None:
    corpus = C.seeded_order(C.load_corpus(corpus_dir))
    if not corpus:
        raise SystemExit(f"No supported documents under {corpus_dir}")
    if quick:
        corpus = corpus[:8]
        sizes = [4, 8]
    sizes = sizes or C.default_sizes(len(corpus))
    batches = C.size_batches(corpus, sizes)

    vault_path = workdir / "vault"
    csv_path = H.RAW_DIR / "db_size.csv"
    fields = [
        "corpus_size",
        "corpus_bytes",
        "db_bytes",
        "blob_bytes",
        "db_dumps_bytes",
        "events_bytes",
        "other_bytes",
        "vault_bytes",
    ]

    # Load already-measured checkpoints so interrupted runs can resume.
    all_rows: list[dict] = []
    done_sizes: set[int] = set()
    if csv_path.exists():
        with csv_path.open(encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                all_rows.append({k: int(row[k]) for k in fields})
                done_sizes.add(int(row["corpus_size"]))

    remaining = [(s, b) for s, b in batches if s not in done_sizes]
    if not remaining:
        print("[db-size] all checkpoints already measured")
    else:
        with H.resumable_vault(workdir) as svc:
            imported = sum(1 for e in svc.list_all_entries() if not e.is_folder)
            if imported:
                print(f"[db-size] resuming from {imported} already imported files")
            for size, _subset in remaining:
                imported = C.import_documents(
                    svc, corpus, imported, size, label="db-size", total=sizes[-1]
                )
                corpus_bytes = sum(p.stat().st_size for p in corpus[:size])
                db = _db_bytes(svc)
                blob = _dir_bytes(VL.blobs_dir(vault_path))
                dumps = _dir_bytes(vault_path / VL.DB_DUMPS_DIR)
                events = _dir_bytes(vault_path / VL.EVENTS_DIR)
                vault = _dir_bytes(vault_path)
                other = max(0, vault - blob - dumps - events)
                all_rows.append(
                    {
                        "corpus_size": size,
                        "corpus_bytes": corpus_bytes,
                        "db_bytes": db,
                        "blob_bytes": blob,
                        "db_dumps_bytes": dumps,
                        "events_bytes": events,
                        "other_bytes": other,
                        "vault_bytes": vault,
                    }
                )
                all_rows.sort(key=lambda r: r["corpus_size"])
                H.write_csv(csv_path, all_rows, fields)
                print(
                    f"[db-size measure] docs={size} vault={vault} "
                    f"(blobs={blob} snapshot={dumps} events={events} other={
                        other
                    }) full_db={db}"
                )

    rows = sorted(all_rows, key=lambda r: r["corpus_size"])

    mib = 1 << 20
    per_size = "\n".join(
        f"  docs={r['corpus_size']:>6}  corpus={r['corpus_bytes'] / mib:7.2f}  "
        f"vault={r['vault_bytes'] / mib:7.2f}  "
        f"[blobs={r['blob_bytes'] / mib:6.2f} snapshot={r['db_dumps_bytes'] / mib:6.2f} "
        f"events={r['events_bytes'] / mib:5.2f} other={r['other_bytes'] / mib:4.2f}]  "
        f"working_db={r['db_bytes'] / mib:6.2f}"
        for r in rows
    )
    last = rows[-1]
    cb = last["corpus_bytes"] or 1
    overhead = (
        f"vault/corpus={last['vault_bytes'] / cb:.3f}x  "
        f"working_db/corpus={last['db_bytes'] / cb:.3f}x  "
        f"blobs/corpus={last['blob_bytes'] / cb:.3f}x  "
        f"snapshot={last['db_dumps_bytes'] / mib:.2f}MiB  "
        f"events={last['events_bytes'] / (1 << 10):.1f}KiB"
    )
    H.write_txt(
        H.RAW_DIR / "db_size.txt",
        "Storage Footprint vs Corpus Size",
        [
            ("On-disk size by corpus size (MiB)", per_size),
            ("Overhead at full corpus", overhead),
        ],
    )


def main() -> None:
    base = H.REPO_ROOT / "test_data" / "search accuracy"
    parser = argparse.ArgumentParser(description="6. Storage footprint benchmark")
    parser.add_argument("--corpus", type=Path, default=base / "search_test_corpus")
    parser.add_argument(
        "--workdir",
        type=Path,
        default=H.REPO_ROOT / "benchmarks" / ".vaults" / "storage",
    )
    parser.add_argument("--sizes", type=int, nargs="*", default=None)
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    run(args.corpus, args.workdir, sizes=args.sizes, quick=args.quick)
    from benchmarks.plotting import plot_db_size

    plot_db_size(H.RAW_DIR)


if __name__ == "__main__":
    main()
