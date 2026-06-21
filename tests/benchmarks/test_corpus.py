import json

import pytest

from benchmarks import _corpus as C


def test_load_corpus_recursive_supported_only(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.pdf").write_bytes(b"%PDF-1.4")
    (tmp_path / "sub" / "b.txt").write_text("hi")
    (tmp_path / "c.bin").write_bytes(b"\x00")  # unsupported
    (tmp_path / "fulltext_search_corpus.txt").write_text("artifact")  # excluded
    files = C.load_corpus(tmp_path)
    names = {p.name for p in files}
    assert names == {"a.pdf", "b.txt"}


def test_size_batches_are_nested_and_capped():
    files = [f"f{i}" for i in range(10)]
    batches = C.size_batches(files, [3, 5, 100])
    sizes = [n for n, _ in batches]
    assert sizes == [3, 5, 10]  # 100 capped to 10
    n0, b0 = batches[0]
    n1, b1 = batches[1]
    assert b0 == b1[:n0]  # nested prefix


def test_load_labels_maps_both_to_all_and_detects_negative(tmp_path):
    p = tmp_path / "labels.json"
    p.write_text(
        json.dumps(
            [
                {"query": "board", "relevant": ["x.pdf"], "scope": "both"},
                {"query": "english", "relevant": ["y.pdf"], "scope": "filename"},
                {"query": "qyzzlephtn", "relevant": [], "scope": "content"},
            ]
        ),
        encoding="utf-8",
    )
    labels = C.load_labels(p)
    assert labels[0].api_scope == "all"
    assert labels[1].api_scope == "filename"
    assert labels[2].is_negative is True


def test_load_labels_rejects_bad_scope(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(
        json.dumps([{"query": "q", "relevant": [], "scope": "wrong"}]), encoding="utf-8"
    )
    with pytest.raises(ValueError):
        C.load_labels(p)
