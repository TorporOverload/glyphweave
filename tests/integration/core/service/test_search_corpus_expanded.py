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


def _fake_extract(path: Path) -> tuple[str, dict[str, str]]:
    suffix = path.suffix.lower()
    if suffix in {".txt", ".md", ".tex"}:
        return path.read_text(encoding="utf-8"), {"kind": suffix.lstrip(".")}
    return (f"Document filename {path.name}", {"kind": suffix.lstrip(".")})


def _populate_vault(vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.services.content.extraction_service._run_kreuzberg_extraction",
        _fake_extract,
    )
    corpus_files = _top_level_supported_corpus_files()
    for source in corpus_files:
        vault_file_service.add_file(source, dest_name=source.name)


class TestBooleanQueryOperators:
    def test_and_operator(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("South African AND framework", limit=50)
        result_names = [r.file_name for r in results]
        assert "aerast_chatdid-integration_main_s.txt" in result_names

    def test_or_operator(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("disk OR Higgs", limit=50)
        result_names = [r.file_name for r in results]
        assert "bitplane_blkcache_master_claude.md" in result_names
        assert "EXO-24-025_temp.tex" in result_names

    def test_not_operator(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("South African NOT framework", limit=50)
        result_names = [r.file_name for r in results]
        assert "aerast_chatdid-integration_main_s.txt" not in result_names

    def test_lowercase_and_or_not_normalized(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("disk and preservation", limit=50)
        result_names = [r.file_name for r in results]
        assert "bitplane_blkcache_master_claude.md" in result_names


class TestQuotedPhraseSearch:
    def test_quoted_exact_phrase(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search('"South African Legal"', limit=50)
        result_names = [r.file_name for r in results]
        assert "aerast_chatdid-integration_main_s.txt" in result_names

    def test_quoted_phrase_partial(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search('"disk preservation"', limit=50)
        result_names = [r.file_name for r in results]
        assert "bitplane_blkcache_master_claude.md" in result_names

    def test_quoted_phrase_no_match(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search('"nonexistent phrase"', limit=50)
        assert len(results) == 0


class TestPartialPrefixMatching:
    def test_prefix_partial_term(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("blk", limit=50)
        result_names = [r.file_name for r in results]
        assert "bitplane_blkcache_master_claude.md" in result_names

    def test_prefix_search_term(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("South", limit=50)
        result_names = [r.file_name for r in results]
        assert "aerast_chatdid-integration_main_s.txt" in result_names

    def test_prefix_multiple_terms(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("Higgs boson", limit=50)
        result_names = [r.file_name for r in results]
        assert "EXO-24-025_temp.tex" in result_names


class TestHyphenatedFilenameSearch:
    def test_hyphenated_filename_token(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("aerast", limit=50)
        result_names = [r.file_name for r in results]
        assert "aerast_chatdid-integration_main_s.txt" in result_names

    def test_hyphenated_full_segment(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("chatdid", limit=50)
        result_names = [r.file_name for r in results]
        assert "aerast_chatdid-integration_main_s.txt" in result_names

    def test_hyphenated_partial_match(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("integration", limit=50)
        result_names = [r.file_name for r in results]
        assert "aerast_chatdid-integration_main_s.txt" in result_names

    def test_hyphenated_compound_segment(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("blkcache", limit=50)
        result_names = [r.file_name for r in results]
        assert "bitplane_blkcache_master_claude.md" in result_names


class TestSpecialCharactersInQueries:
    def test_underscore_token(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("master_claude", limit=50)
        result_names = [r.file_name for r in results]
        assert "bitplane_blkcache_master_claude.md" in result_names

    def test_search_exact_filename(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("EXO-24-025_temp.tex", limit=50)
        result_names = [r.file_name for r in results]
        assert "EXO-24-025_temp.tex" in result_names

    def test_content_with_numbers(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("24-025", limit=50)
        result_names = [r.file_name for r in results]
        assert "EXO-24-025_temp.tex" in result_names

    def test_search_astrisk_no_crash(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("*", limit=50)
        assert isinstance(results, list)

    def test_empty_query_returns_empty(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("", limit=50)
        assert len(results) == 0

    def test_whitespace_only_query(self, vault_file_service: VaultFileService, monkeypatch: pytest.MonkeyPatch) -> None:
        _populate_vault(vault_file_service, monkeypatch)
        results = vault_file_service.search("   ", limit=50)
        assert len(results) == 0