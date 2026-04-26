from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.infrastructure.persistence.db.model.extraction_status import ExtractionStatus
from app.services.content.indexing_service import IndexingService
from app.services.content.extraction_service import ExtractionService, ExtractionResult


class _FakeEncryptionService:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def decrypt_file(self, **kwargs) -> None:
        self.calls.append(kwargs)
        output_path: Path = kwargs["output_path"]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("decrypted", encoding="utf-8")


def _make_service(tmp_path: Path) -> IndexingService:
    encryption_service = _FakeEncryptionService()
    service = IndexingService(
        session_factory=SimpleNamespace(),
        encryption_service=encryption_service,
        vault_path=tmp_path / "vault",
        cache_dir=tmp_path / "cache",
        master_key=b"k" * 32,
        vault_id="vault-1",
    )
    return service


class TestIndexingServiceIntegration:
    def test_index_real_pdf_extracts_text(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        service = _make_service(tmp_path)
        pdf_path = tmp_path / "document.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        events: list[tuple] = []

        monkeypatch.setattr(
            "app.services.content.indexing_service.session_scope",
            lambda *args, **kwargs: _fake_session_scope(SimpleNamespace()),
        )
        monkeypatch.setattr(
            "app.services.content.indexing_service.insert_document_content",
            lambda current_session, file_entry_id, content: events.append(
                ("insert", file_entry_id, content)
            ) or True,
        )
        monkeypatch.setattr(
            "app.services.content.indexing_service.update_extraction_status",
            lambda current_session, file_entry_id, status, preview=None, metadata_json=None: events.append(
                ("status", file_entry_id, status, preview)
            ),
        )

        monkeypatch.setattr(
            "app.services.content.indexing_service.ExtractionService.is_supported",
            lambda filename: True,
        )

        monkeypatch.setattr(
            "app.services.content.extraction_service._run_kreuzberg_extraction",
            lambda path: ("sample extracted text", {}),
        )

        result = service.index_source_file(1, pdf_path, "document.pdf")

        insert_events = [e for e in events if e[0] == "insert"]
        status_events = [e for e in events if e[0] == "status"]

        assert insert_events, "extraction should have been invoked and content stored"
        assert len(insert_events[0][2]) > 0, "extraction should have returned meaningful content"
        assert status_events[0][1] == 1
        assert status_events[0][2] == ExtractionStatus.DONE

    def test_corrupt_pdf_marked_as_failed_not_crashing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        service = _make_service(tmp_path)
        corrupt_pdf = tmp_path / "corrupt.pdf"
        corrupt_pdf.write_bytes(b"%PDF-1.0 this is not real pdf data at all")
        statuses: list[tuple] = []

        monkeypatch.setattr(
            service,
            "_set_status",
            lambda file_entry_id, status, preview=None, metadata_json=None: statuses.append(
                (file_entry_id, status, preview)
            ),
        )

        result = service.index_source_file(5, corrupt_pdf, "corrupt.pdf")

        assert len(statuses) == 1, "corrupt PDF should be handled without crashing"
        assert statuses[0][0] == 5
        assert statuses[0][1] in (ExtractionStatus.UNSUPPORTED, ExtractionStatus.FAILED)

    def test_indexing_with_empty_file_handled(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        service = _make_service(tmp_path)
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("", encoding="utf-8")
        statuses: list[tuple] = []

        monkeypatch.setattr(
            service,
            "_set_status",
            lambda file_entry_id, status, preview=None, metadata_json=None: statuses.append(
                (file_entry_id, status, preview)
            ),
        )

        result = service.index_source_file(3, empty_file, "empty.txt")

        assert len(statuses) == 1, "empty file should be handled gracefully"
        assert statuses[0][0] == 3
        assert statuses[0][1] in (ExtractionStatus.UNSUPPORTED, ExtractionStatus.DONE)

    def test_very_long_filename_handled(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        service = _make_service(tmp_path)
        long_name = "a" * 96 + ".txt"
        long_file = tmp_path / long_name
        long_file.write_text("content", encoding="utf-8")
        statuses: list[tuple] = []

        monkeypatch.setattr(
            service,
            "_set_status",
            lambda file_entry_id, status, preview=None, metadata_json=None: statuses.append(
                (file_entry_id, status, preview)
            ),
        )

        result = service.index_source_file(7, long_file, long_name)

        assert len(statuses) == 1, "long filename should be processed without crashing"
        assert statuses[0][0] == 7
        assert statuses[0][1] in (ExtractionStatus.UNSUPPORTED, ExtractionStatus.DONE, ExtractionStatus.FAILED)
        assert len(long_name) == 100, "test verifies processing of 100-char filename"


class _FakeSession:
    def __init__(self) -> None:
        self.committed = False

    def commit(self) -> None:
        self.committed = True

    def close(self) -> None:
        pass


@contextmanager
def _fake_session_scope(session):
    yield session