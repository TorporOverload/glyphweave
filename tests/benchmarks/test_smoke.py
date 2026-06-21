import json

from benchmarks import _harness as H


def test_vault_unlock_quick(tmp_path, monkeypatch):
    monkeypatch.setattr(H, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(H, "FIG_DIR", tmp_path / "fig")
    import benchmarks.plotting as P

    monkeypatch.setattr(P, "FIG_DIR", tmp_path / "fig")

    from benchmarks import bench_vault_unlock as B

    B.run(tmp_path / "wd", kdf=H.FAST_KDF, quick=True)
    assert (tmp_path / "raw" / "unlock_breakdown.csv").stat().st_size > 0
    assert (tmp_path / "raw" / "unlock_kdf_sweep.csv").stat().st_size > 0

    P.plot_vault_unlock(tmp_path / "raw")
    assert (tmp_path / "fig" / "vault_unlock.pdf").exists()


def test_fuse_throughput_quick(tmp_path, monkeypatch):
    monkeypatch.setattr(H, "RAW_DIR", tmp_path / "raw")
    import benchmarks.plotting as P

    monkeypatch.setattr(P, "FIG_DIR", tmp_path / "fig")

    from benchmarks import bench_fuse_throughput as B

    B.run(tmp_path / "wd", quick=True)  # quick => in-process layer only
    csv_path = tmp_path / "raw" / "fuse_throughput.csv"
    assert csv_path.stat().st_size > 0
    assert "in_process" in csv_path.read_text(encoding="utf-8")

    P.plot_fuse_throughput(tmp_path / "raw")
    assert (tmp_path / "fig" / "fuse_throughput.pdf").exists()


def test_search_latency_quick(tmp_path, monkeypatch):
    monkeypatch.setattr(H, "RAW_DIR", tmp_path / "raw")
    import benchmarks.plotting as P

    monkeypatch.setattr(P, "FIG_DIR", tmp_path / "fig")

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for i in range(8):
        (corpus / f"doc_{i}.txt").write_text(
            f"annual report data document {i} ދިވެހި", encoding="utf-8"
        )
    labels = tmp_path / "labels.json"
    labels.write_text(
        json.dumps(
            [
                {
                    "query": "data",
                    "relevant": ["doc_0.txt"],
                    "scope": "content",
                },  # positive: ignored
                {
                    "query": "zzznotpresent",
                    "relevant": [],
                    "scope": "content",
                },  # miss: borrowed
                {
                    "query": "glacier calving antarctica",
                    "relevant": [],
                    "scope": "both",
                },  # miss: borrowed
            ]
        ),
        encoding="utf-8",
    )

    from benchmarks import bench_search_latency as B

    B.run(corpus, tmp_path / "wd", labels_path=labels, quick=True)
    csv_path = tmp_path / "raw" / "search_latency.csv"
    assert csv_path.stat().st_size > 0

    import csv as _csv

    with csv_path.open(encoding="utf-8") as fh:
        rows = list(_csv.DictReader(fh))
    negatives = [r for r in rows if r["query_type"].startswith("negative_")]
    assert negatives, "borrowed zero-result queries should be measured"
    # the runtime check only times misses that genuinely returned nothing
    assert all(r["result_count"] == "0" for r in negatives)

    P.plot_search_latency(tmp_path / "raw")
    assert (tmp_path / "fig" / "search_latency.pdf").exists()


def test_db_size_quick(tmp_path, monkeypatch):
    monkeypatch.setattr(H, "RAW_DIR", tmp_path / "raw")
    import benchmarks.plotting as P

    monkeypatch.setattr(P, "FIG_DIR", tmp_path / "fig")

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for i in range(8):
        (corpus / f"doc_{i}.txt").write_text(
            ("alpha beta gamma " * 200) + str(i), encoding="utf-8"
        )

    from benchmarks import bench_db_size as B

    B.run(corpus, tmp_path / "wd", quick=True)
    csv_path = tmp_path / "raw" / "db_size.csv"
    assert csv_path.stat().st_size > 0

    import csv as _csv

    with csv_path.open(encoding="utf-8") as fh:
        rows = list(_csv.DictReader(fh))
    assert rows, "db_size benchmark should record at least one corpus size"
    # the live DB and the raw corpus must both register non-zero bytes
    assert all(int(r["corpus_bytes"]) > 0 for r in rows)
    assert int(rows[-1]["db_bytes"]) > 0
    # the in-vault breakdown (blobs + snapshot + events + other) must account
    # for the entire vault footprint at every corpus size
    for r in rows:
        parts = (
            int(r["blob_bytes"])
            + int(r["db_dumps_bytes"])
            + int(r["events_bytes"])
            + int(r["other_bytes"])
        )
        assert parts == int(r["vault_bytes"]), r

    P.plot_db_size(tmp_path / "raw")
    assert (tmp_path / "fig" / "db_size.pdf").exists()


def test_concurrent_access_quick(tmp_path, monkeypatch):
    monkeypatch.setattr(H, "RAW_DIR", tmp_path / "raw")
    import benchmarks.plotting as P

    monkeypatch.setattr(P, "FIG_DIR", tmp_path / "fig")

    from benchmarks import bench_concurrent_access as B

    B.run(tmp_path / "wd", quick=True)  # cap=4, real mounts
    assert (tmp_path / "raw" / "concurrent_access.csv").stat().st_size > 0

    P.plot_concurrent_access(tmp_path / "raw")
    assert (tmp_path / "fig" / "concurrent_access.pdf").exists()


def test_search_accuracy_quick(tmp_path, monkeypatch):
    monkeypatch.setattr(H, "RAW_DIR", tmp_path / "raw")
    import benchmarks.plotting as P

    monkeypatch.setattr(P, "FIG_DIR", tmp_path / "fig")

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "alpha.txt").write_text(
        "the alpha keyword apple banana", encoding="utf-8"
    )
    (corpus / "beta.txt").write_text("the beta keyword apple cherry", encoding="utf-8")
    labels = tmp_path / "labels.json"
    labels.write_text(
        json.dumps(
            [
                {
                    "query": "apple",
                    "relevant": ["alpha.txt", "beta.txt"],
                    "scope": "content",
                },
                {"query": "alpha", "relevant": ["alpha.txt"], "scope": "filename"},
                {"query": "zzznotpresent", "relevant": [], "scope": "content"},
            ]
        ),
        encoding="utf-8",
    )

    from benchmarks import bench_search_accuracy as B

    B.run(corpus, labels, tmp_path / "wd", quick=True)
    assert (tmp_path / "raw" / "accuracy_per_query.csv").stat().st_size > 0

    P.plot_search_accuracy(tmp_path / "raw")
    assert (tmp_path / "fig" / "accuracy_pr_curve.pdf").exists()
