from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services.content.extraction_service import ExtractionService
from app.services.vault_files.vault_file_service import VaultFileService

TEST_CORPUS_DIR = (
    Path(__file__).resolve().parents[4] / "test_data" / "test_corpus"
)


def _top_level_supported_corpus_files() -> list[Path]:
    return sorted(
        path
        for path in TEST_CORPUS_DIR.iterdir()
        if path.is_file() and ExtractionService.is_supported(path.name)
    )


def _filename_query_token(path: Path) -> str:
    tokens = [token for token in re.split(r"[^0-9A-Za-z]+", path.stem) if token]
    for token in tokens:
        if len(token) >= 4:
            return token
    if tokens:
        return tokens[0]
    raise ValueError(f"No searchable token found for {path.name}")


def _fake_extract(path: Path) -> tuple[str, dict[str, str]]:
    suffix = path.suffix.lower()
    if suffix in {".txt", ".md", ".tex"}:
        return path.read_text(encoding="utf-8"), {"kind": suffix.lstrip(".")}
    return (f"Document filename {path.name}", {"kind": suffix.lstrip(".")})


def test_search_indexes_corpus_filenames_and_phrases(
    vault_file_service: VaultFileService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus_files = _top_level_supported_corpus_files()
    assert corpus_files, "Expected supported files in test corpus"

    monkeypatch.setattr(
        "app.services.content.extraction_service._run_kreuzberg_extraction",
        _fake_extract,
    )

    for source in corpus_files:
        result = vault_file_service.add_file(source, dest_name=source.name)
        assert result.file_name == source.name

    root_entries = [entry for entry in vault_file_service.list_root_entries() if not entry.is_folder]
    assert len(root_entries) == len(corpus_files)

    for source in corpus_files:
        token = _filename_query_token(source)
        results = vault_file_service.search(token, limit=50)
        assert any(result.file_name == source.name for result in results), (
            f"Filename search for token '{token}' did not return {source.name}"
        )

    phrase_expectations = [
        (
            "South African Legal framework",
            "aerast_chatdid-integration_main_s.txt",
        ),
        (
            "disk preservation toolkit",
            "bitplane_blkcache_master_claude.md",
        ),
        (
            "Search for exotic Higgs boson decays",
            "EXO-24-025_temp.tex",
        ),
    ]
    for phrase, expected_name in phrase_expectations:
        results = vault_file_service.search(phrase, limit=20)
        assert any(result.file_name == expected_name for result in results), (
            f"Phrase search for '{phrase}' did not return {expected_name}"
        )
