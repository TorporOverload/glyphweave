from benchmarks import _harness as H


def test_summarize_known_values():
    s = H.summarize([1.0, 2.0, 3.0, 4.0, 5.0])
    assert s.n == 5
    assert s.mean == 3.0
    assert s.median == 3.0
    assert s.min == 1.0
    assert s.max == 5.0
    assert 4.5 <= s.p95 <= 5.0


def test_summarize_empty_is_safe():
    s = H.summarize([])
    assert s.n == 0 and s.mean == 0.0


def test_measure_collects_repeats_not_warmup():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1

    samples = H.measure(fn, repeats=4, warmup=2)
    assert len(samples) == 4
    assert calls["n"] == 6
    assert all(x >= 0.0 for x in samples)


def test_write_csv_roundtrip(tmp_path):
    import csv
    p = tmp_path / "x.csv"
    H.write_csv(p, [{"a": 1, "b": 2}, {"a": 3, "b": 4}], ["a", "b"])
    rows = list(csv.DictReader(p.open(encoding="utf-8")))
    assert rows[0]["a"] == "1" and rows[1]["b"] == "4"


def test_write_txt_has_title_and_sections(tmp_path):
    p = tmp_path / "x.txt"
    H.write_txt(p, "My Report", [("Section A", "body a"), ("Section B", "body b")])
    text = p.read_text(encoding="utf-8")
    assert "My Report" in text and "Section A" in text and "body b" in text


def test_capture_meta_keys():
    meta = H.capture_meta({"benchmark": "demo"})
    for key in ("timestamp", "platform", "python", "git_sha", "packages", "benchmark"):
        assert key in meta


def test_free_disk_bytes_positive(tmp_path):
    assert H.free_disk_bytes(tmp_path) > 0


def test_temp_vault_opens_and_is_usable(tmp_path):
    with H.temp_vault(tmp_path) as svc:
        entries = svc.list_root_entries()
        assert entries == [] or isinstance(entries, list)


def test_kdf_constants():
    assert H.FAST_KDF.memory_kb == 8 * 1024
    assert H.FAST_KDF.iterations == 1
    assert H.PROD_KDF.memory_kb >= 256 * 1024  # production is heavy
