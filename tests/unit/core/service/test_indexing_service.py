from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.orm.exc import DetachedInstanceError

from app.infrastructure.persistence.db.model.extraction_status import ExtractionStatus
from app.services.content.extraction_service import ExtractionService
from app.services.content.extraction_service import ExtractionResult
from app.services.content.indexing_service import IndexingService


class _FakeEncryptionService:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def decrypt_file(self, **kwargs) -> None:
        self.calls.append(kwargs)
        output_path: Path = kwargs["output_path"]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("decrypted", encoding="utf-8")


@contextmanager
def _fake_session_scope(session):
    yield session


def _make_service(tmp_path: Path) -> tuple[IndexingService, _FakeEncryptionService]:
    encryption_service = _FakeEncryptionService()
    service = IndexingService(
        session_factory=SimpleNamespace(),
        encryption_service=encryption_service,
        vault_path=tmp_path / "vault",
        cache_dir=tmp_path / "cache",
        master_key=b"k" * 32,
        vault_id="vault-1",
    )
    return service, encryption_service


def _make_entry(*, file_id: str = "file-1", entry_id: int = 1, blob_ids=None):
    if blob_ids is None:
        blob_ids = ["blob-1.enc"]
    return SimpleNamespace(
        id=entry_id,
        file_id=file_id,
        blobs=[SimpleNamespace(blob_id=blob_id) for blob_id in blob_ids],
    )


class _DetachedEntry:
    def __init__(self, *, entry_id: int, file_id: str) -> None:
        self.id = entry_id
        self.file_id = file_id

    @property
    def blobs(self):
        raise DetachedInstanceError("detached")


class _FakeFileEntryQuery:
    def __init__(self, entry):
        self._entry = entry

    def options(self, *args, **kwargs):
        return self

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._entry


class _FakeScalarResult:
    def __init__(self, entry):
        self._entry = entry

    def unique(self):
        return self

    def first(self):
        return self._entry


class _FakeLookupSession:
    def __init__(self, entry):
        self._entry = entry

    def query(self, _model):
        return _FakeFileEntryQuery(self._entry)

    def scalars(self, stmt):
        return _FakeScalarResult(self._entry)


def test_index_file_entry_skips_unsupported_format(tmp_path: Path) -> None:
    service, encryption_service = _make_service(tmp_path)
    entry = _make_entry()
    statuses: list[tuple] = []
    temp_path = tmp_path / "cache" / ".tmp" / "temp.png"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path.write_bytes(b"\x89PNG\r\n")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(service, "_decrypt_to_temp", lambda *args: temp_path)
    monkeypatch.setattr(
        service,
        "_set_status",
        lambda file_entry_id, status, preview=None, metadata_json=None: statuses.append(
            (file_entry_id, status, preview, metadata_json)
        ),
    )

    result = service.index_file_entry(entry, "photo.png")
    monkeypatch.undo()

    assert result is False
    assert encryption_service.calls == []
    assert statuses[0][0:3] == (1, ExtractionStatus.UNSUPPORTED, "")
    assert statuses[0][3] is not None
    metadata = json.loads(statuses[0][3])
    assert metadata["file_name"] == "temp.png"
    assert metadata["extension"] == ".png"
    assert metadata["mime_type"] == "image/png"
    assert metadata["size_bytes"] == 6
    assert metadata["text_extraction_supported"] is False
    assert not temp_path.exists()


def test_index_source_file_marks_unsupported_with_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, encryption_service = _make_service(tmp_path)
    source = tmp_path / "photo.png"
    source.write_bytes(b"\x89PNG\r\n")
    statuses: list[tuple] = []

    monkeypatch.setattr(
        service,
        "_set_status",
        lambda file_entry_id, status, preview=None, metadata_json=None: statuses.append(
            (file_entry_id, status, preview, metadata_json)
        ),
    )

    result = service.index_source_file(5, source, "photo.png")

    assert result is False
    assert encryption_service.calls == []
    assert statuses[0][0:3] == (5, ExtractionStatus.UNSUPPORTED, "")
    assert statuses[0][3] is not None
    metadata = json.loads(statuses[0][3])
    assert metadata["extension"] == ".png"
    assert metadata["mime_type"] == "image/png"
    assert metadata["text_extraction_supported"] is False


def test_index_source_file_marks_invalid_pdf_parse_as_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = _make_service(tmp_path)
    source = tmp_path / "broken.pdf"
    source.write_bytes(b"%PDF-1.4\n")
    statuses: list[tuple] = []

    monkeypatch.setattr(
        service,
        "_set_status",
        lambda file_entry_id, status, preview=None, metadata_json=None: statuses.append(
            (file_entry_id, status, preview, metadata_json)
        ),
    )
    monkeypatch.setattr(
        "app.services.content.indexing_service.ExtractionService.extract",
        lambda path: ExtractionResult(
            error=(
                "ParsingError: Invalid PDF: PdfiumLibraryInternalError: "
                "FormatError: Invalid PDF: PdfiumLibraryInternalError: FormatError"
            ),
            unsupported=True,
            metadata={"kind": "pdf"},
        ),
    )

    result = service.index_source_file(7, source, "broken.pdf")

    assert result is False
    assert statuses[0][0:3] == (7, ExtractionStatus.UNSUPPORTED, "")


def test_extraction_service_marks_invalid_pdf_parse_as_unsupported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "broken.pdf"
    source.write_bytes(b"%PDF-1.4\n")

    def _raise(_path: Path):
        raise RuntimeError(
            "ParsingError: Invalid PDF: PdfiumLibraryInternalError: "
            "FormatError: Invalid PDF: PdfiumLibraryInternalError: FormatError"
        )

    monkeypatch.setattr(
        "app.services.content.extraction_service._run_kreuzberg_extraction",
        _raise,
    )

    result = ExtractionService.extract(source)

    assert result.error is not None
    assert result.unsupported is True


def test_extraction_service_marks_password_protected_pdf_as_unsupported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "protected.pdf"
    source.write_bytes(b"%PDF-1.4\n")

    def _raise(_path: Path):
        raise RuntimeError(
            "ParsingError: PDF is password-protected: PDF is password-protected"
        )

    monkeypatch.setattr(
        "app.services.content.extraction_service._run_kreuzberg_extraction",
        _raise,
    )

    result = ExtractionService.extract(source)

    assert result.error is not None
    assert result.unsupported is True


def test_extraction_service_marks_password_protected_docx_as_unsupported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "protected.docx"
    source.write_bytes(b"PK\x03\x04")

    def _raise(_path: Path):
        raise RuntimeError("ParsingError: DOCX is password-protected")

    monkeypatch.setattr(
        "app.services.content.extraction_service._run_kreuzberg_extraction",
        _raise,
    )

    result = ExtractionService.extract(source)

    assert result.error is not None
    assert result.unsupported is True


def test_extraction_service_marks_encrypted_xlsx_as_unsupported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "protected.xlsx"
    source.write_bytes(b"PK\x03\x04")

    def _raise(_path: Path):
        raise RuntimeError("ParsingError: Encrypted workbook")

    monkeypatch.setattr(
        "app.services.content.extraction_service._run_kreuzberg_extraction",
        _raise,
    )

    result = ExtractionService.extract(source)

    assert result.error is not None
    assert result.unsupported is True


def test_index_file_entry_skips_when_no_blobs(tmp_path: Path) -> None:
    service, encryption_service = _make_service(tmp_path)
    entry = _make_entry(blob_ids=[])

    result = service.index_file_entry(entry, "notes.txt")

    assert result is False
    assert encryption_service.calls == []


def test_index_source_file_uses_plaintext_without_decrypting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, encryption_service = _make_service(tmp_path)
    session = SimpleNamespace()
    source = tmp_path / "report.txt"
    source.write_text("hello", encoding="utf-8")
    events: list[tuple] = []

    monkeypatch.setattr(
        "app.services.content.indexing_service.ExtractionService.extract",
        lambda path: ExtractionResult(content="hello", preview="hello", metadata={}),
    )
    monkeypatch.setattr(
        "app.services.content.indexing_service.session_scope",
        lambda *args, **kwargs: _fake_session_scope(session),
    )
    monkeypatch.setattr(
        "app.services.content.indexing_service.insert_document_content",
        lambda current_session, file_entry_id, content: events.append(
            ("insert", current_session, file_entry_id, content)
        )
        or True,
    )
    monkeypatch.setattr(
        "app.services.content.indexing_service.update_extraction_status",
        lambda current_session,
        file_entry_id,
        status,
        preview=None,
        metadata_json=None: events.append(
            ("status", current_session, file_entry_id, status, preview, metadata_json)
        ),
    )

    result = service.index_source_file(5, source, "report.txt")

    assert result is True
    assert encryption_service.calls == []
    assert events[0] == ("insert", session, 5, "hello")
    assert events[1][0:5] == ("status", session, 5, ExtractionStatus.DONE, "hello")
    metadata = json.loads(events[1][5])
    assert metadata["file_name"] == "report.txt"
    assert metadata["extension"] == ".txt"
    assert metadata["text_extraction_supported"] is True


def test_index_file_entry_reloades_detached_entry_blobs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, encryption_service = _make_service(tmp_path)
    entry = _DetachedEntry(entry_id=7, file_id="detached-file")
    loaded_entry = _make_entry(
        file_id="loaded-file", entry_id=7, blob_ids=["blob-9.enc"]
    )
    lookup_session = _FakeLookupSession(loaded_entry)
    write_session = SimpleNamespace()
    temp_path = tmp_path / "cache" / ".tmp" / "temp.txt"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path.write_text("hello", encoding="utf-8")
    scope_calls: list[bool] = []

    def _session_scope(*args, **kwargs):
        scope_calls.append(bool(kwargs.get("commit", True)))
        if kwargs.get("commit", True) is False:
            return _fake_session_scope(lookup_session)
        return _fake_session_scope(write_session)

    monkeypatch.setattr(
        "app.services.content.indexing_service.session_scope",
        _session_scope,
    )
    monkeypatch.setattr(service, "_decrypt_to_temp", lambda *args: temp_path)
    monkeypatch.setattr(
        "app.services.content.indexing_service.ExtractionService.extract",
        lambda path: ExtractionResult(content="hello", preview="hello", metadata={}),
    )
    monkeypatch.setattr(
        "app.services.content.indexing_service.insert_document_content",
        lambda current_session, file_entry_id, content: True,
    )
    status_calls: list[tuple] = []
    monkeypatch.setattr(
        "app.services.content.indexing_service.update_extraction_status",
        lambda current_session,
        file_entry_id,
        status,
        preview=None,
        metadata_json=None: status_calls.append(
            (current_session, file_entry_id, status, preview, metadata_json)
        ),
    )

    result = service.index_file_entry(entry, "report.txt")

    assert result is True
    assert encryption_service.calls == []
    assert scope_calls == [False, True]
    assert status_calls[0][0:4] == (write_session, 7, ExtractionStatus.DONE, "hello")
    metadata = json.loads(status_calls[0][4])
    assert metadata["file_name"] == "temp.txt"
    assert metadata["extension"] == ".txt"
    assert not temp_path.exists()


def test_index_file_entry_indexes_supported_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = _make_service(tmp_path)
    entry = _make_entry()
    session = SimpleNamespace()
    temp_path = tmp_path / "cache" / ".tmp" / "temp.txt"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path.write_text("hello", encoding="utf-8")
    events: list[tuple] = []

    monkeypatch.setattr(service, "_decrypt_to_temp", lambda *args: temp_path)
    monkeypatch.setattr(
        "app.services.content.indexing_service.ExtractionService.extract",
        lambda path: ExtractionResult(
            content="Þ‹Þ¨ÞˆÞ¬Þ€Þ¨ Þ„Þ¦ÞÞ°",
            preview="Þ‹Þ¨ÞˆÞ¬Þ€Þ¨",
            metadata={"lang": "dv"},
        ),
    )
    monkeypatch.setattr(
        "app.services.content.indexing_service.session_scope",
        lambda *args, **kwargs: _fake_session_scope(session),
    )
    monkeypatch.setattr(
        "app.services.content.indexing_service.insert_document_content",
        lambda current_session, file_entry_id, content: events.append(
            ("insert", current_session, file_entry_id, content)
        )
        or True,
    )
    monkeypatch.setattr(
        "app.services.content.indexing_service.update_extraction_status",
        lambda current_session,
        file_entry_id,
        status,
        preview=None,
        metadata_json=None: events.append(
            ("status", current_session, file_entry_id, status, preview, metadata_json)
        ),
    )

    result = service.index_file_entry(entry, "report.txt")

    assert result is True
    assert events[0] == ("insert", session, 1, "Þ‹Þ¨ÞˆÞ¬Þ€Þ¨ Þ„Þ¦ÞÞ°")
    assert events[1][0:4] == ("status", session, 1, ExtractionStatus.DONE)
    assert events[1][4] == "Þ‹Þ¨ÞˆÞ¬Þ€Þ¨"
    metadata = json.loads(events[1][5])
    assert metadata["file_name"] == "temp.txt"
    assert metadata["extension"] == ".txt"
    assert metadata["lang"] == "dv"
    assert not temp_path.exists()


def test_index_file_entry_marks_failed_on_extraction_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = _make_service(tmp_path)
    entry = _make_entry()
    temp_path = tmp_path / "cache" / ".tmp" / "temp.txt"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path.write_text("hello", encoding="utf-8")
    statuses: list[tuple] = []

    monkeypatch.setattr(service, "_decrypt_to_temp", lambda *args: temp_path)
    monkeypatch.setattr(
        "app.services.content.indexing_service.ExtractionService.extract",
        lambda path: ExtractionResult(error="extract failed", metadata={"kind": "txt"}),
    )
    monkeypatch.setattr(
        service,
        "_set_status",
        lambda file_entry_id, status, preview=None, metadata_json=None: statuses.append(
            (file_entry_id, status, preview, metadata_json)
        ),
    )

    result = service.index_file_entry(entry, "report.txt")

    assert result is False
    assert statuses[0][0:3] == (1, ExtractionStatus.FAILED, "")
    metadata = json.loads(statuses[0][3])
    assert metadata["file_name"] == "temp.txt"
    assert metadata["kind"] == "txt"
    assert not temp_path.exists()


def test_index_file_entry_marks_done_for_empty_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = _make_service(tmp_path)
    entry = _make_entry()
    temp_path = tmp_path / "cache" / ".tmp" / "temp.txt"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path.write_text("hello", encoding="utf-8")
    statuses: list[tuple] = []

    monkeypatch.setattr(service, "_decrypt_to_temp", lambda *args: temp_path)
    monkeypatch.setattr(
        "app.services.content.indexing_service.ExtractionService.extract",
        lambda path: ExtractionResult(
            content="   ", preview="", metadata={"empty": True}
        ),
    )
    monkeypatch.setattr(
        service,
        "_set_status",
        lambda file_entry_id, status, preview=None, metadata_json=None: statuses.append(
            (file_entry_id, status, preview, metadata_json)
        ),
    )

    result = service.index_file_entry(entry, "report.txt")

    assert result is True
    assert statuses[0][0:3] == (1, ExtractionStatus.DONE, "")
    metadata = json.loads(statuses[0][3])
    assert metadata["file_name"] == "temp.txt"
    assert metadata["empty"] is True
    assert not temp_path.exists()


def test_index_file_entry_marks_failed_when_insert_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = _make_service(tmp_path)
    entry = _make_entry()
    session = SimpleNamespace()
    temp_path = tmp_path / "cache" / ".tmp" / "temp.txt"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path.write_text("hello", encoding="utf-8")
    events: list[tuple] = []

    monkeypatch.setattr(service, "_decrypt_to_temp", lambda *args: temp_path)
    monkeypatch.setattr(
        "app.services.content.indexing_service.ExtractionService.extract",
        lambda path: ExtractionResult(content="hello", preview="hello", metadata={}),
    )
    monkeypatch.setattr(
        "app.services.content.indexing_service.session_scope",
        lambda *args, **kwargs: _fake_session_scope(session),
    )
    monkeypatch.setattr(
        "app.services.content.indexing_service.insert_document_content",
        lambda current_session, file_entry_id, content: False,
    )
    monkeypatch.setattr(
        "app.services.content.indexing_service.update_extraction_status",
        lambda current_session,
        file_entry_id,
        status,
        preview=None,
        metadata_json=None: events.append(
            (file_entry_id, status, preview, metadata_json)
        ),
    )

    result = service.index_file_entry(entry, "report.txt")

    assert result is False
    assert events[0][0:3] == (1, ExtractionStatus.FAILED, "hello")
    metadata = json.loads(events[0][3])
    assert metadata["file_name"] == "temp.txt"
    assert metadata["extension"] == ".txt"
    assert not temp_path.exists()


def test_index_file_entry_cleans_temp_file_on_unexpected_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = _make_service(tmp_path)
    entry = _make_entry()
    temp_path = tmp_path / "cache" / ".tmp" / "temp.txt"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path.write_text("hello", encoding="utf-8")
    statuses: list[tuple] = []

    monkeypatch.setattr(service, "_decrypt_to_temp", lambda *args: temp_path)

    def _raise(_path: Path) -> ExtractionResult:
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "app.services.content.indexing_service.ExtractionService.extract",
        _raise,
    )
    monkeypatch.setattr(
        service,
        "_set_status",
        lambda file_entry_id, status, preview=None, metadata_json=None: statuses.append(
            (file_entry_id, status, preview, metadata_json)
        ),
    )

    result = service.index_file_entry(entry, "report.txt")

    assert result is False
    assert statuses == [(1, ExtractionStatus.FAILED, "", None)]
    assert not temp_path.exists()
