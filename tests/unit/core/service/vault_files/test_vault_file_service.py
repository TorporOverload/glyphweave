from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.runtime_layout import runtime_cache_dir
from app.core.service.models import AddFileResult, VaultContext
from app.core.service.vault_file_service import VaultFileService


class _MasterKey:
    def __init__(self, value: bytes) -> None:
        self._value = value

    def view(self) -> memoryview:
        return memoryview(self._value)


def test_build_indexing_service_returns_none_when_context_incomplete(tmp_path: Path) -> None:
    service = VaultFileService(VaultContext(app_data_dir=tmp_path))

    assert service._build_indexing_service() is None


def test_build_indexing_service_uses_runtime_cache_dir(tmp_path: Path) -> None:
    context = VaultContext(
        app_data_dir=tmp_path,
        vault_id="vault-1",
        vault_path=tmp_path / "vault",
        local_data_path=tmp_path / "local",
        session_factory=object(),
        encryption_service=object(),
        master_key=_MasterKey(b"k" * 32),
    )
    service = VaultFileService(context)

    indexing = service._build_indexing_service()

    assert indexing is not None
    assert indexing._cache_dir == runtime_cache_dir(context.local_data_path)


def test_add_file_passes_indexing_service_to_import(monkeypatch, tmp_path: Path) -> None:
    context = VaultContext(
        app_data_dir=tmp_path,
        vault_id="vault-1",
        vault_path=tmp_path / "vault",
        local_data_path=tmp_path / "local",
        session_factory=object(),
        encryption_service=object(),
        file_service=object(),
        folder_service=object(),
        master_key=_MasterKey(b"k" * 32),
    )
    service = VaultFileService(context)
    source = tmp_path / "report.txt"
    source.write_text("hello", encoding="utf-8")
    captured = {}

    monkeypatch.setattr(
        "app.core.service.vault_file_service.add_file_to_vault",
        lambda *args, **kwargs: captured.update(kwargs)
        or AddFileResult(
            file_name="report.txt",
            deduplicated=False,
            file_id="f-1",
            original_size=5,
            encrypted_size=10,
            blob_count=1,
            indexed=True,
        ),
    )

    result = service.add_file(source)

    assert result.indexed is True
    assert captured["indexing_service"] is not None


def test_reindex_pending_retries_supported_pending_and_failed_entries(
    monkeypatch, tmp_path: Path
) -> None:
    context = VaultContext(app_data_dir=tmp_path, session_factory=object())
    service = VaultFileService(context)
    entries = [
        SimpleNamespace(
            id=1,
            references=[SimpleNamespace(name="report.txt")],
        ),
        SimpleNamespace(
            id=2,
            references=[SimpleNamespace(name="failed.docx")],
        ),
        SimpleNamespace(
            id=3,
            references=[SimpleNamespace(name="photo.png")],
        ),
    ]
    session = object()
    calls: list[tuple[int, str]] = []

    monkeypatch.setattr(
        "app.core.service.vault_file_service.session_scope",
        lambda *args, **kwargs: __import__("contextlib").nullcontext(session),
    )
    monkeypatch.setattr(
        "app.core.service.vault_file_service.get_retriable_extractions",
        lambda current_session, limit: entries,
    )
    monkeypatch.setattr(
        service,
        "_build_indexing_service",
        lambda: SimpleNamespace(
            index_file_entry=lambda entry, filename: calls.append((entry.id, filename))
            or entry.id == 1
        ),
    )

    success, failed = service.reindex_pending()

    assert calls == [(1, "report.txt"), (2, "failed.docx")]
    assert success == 1
    assert failed == 1


def test_reindex_pending_delegates_supported_name_selection(tmp_path: Path) -> None:
    entry = SimpleNamespace(
        references=[
            SimpleNamespace(name="photo.png"),
            SimpleNamespace(name="ދިވެހި.txt"),
        ]
    )

    assert VaultFileService._select_supported_reference_name(entry) == "ދިވެހި.txt"


def test_get_file_reference_metadata_returns_parsed_metadata(tmp_path: Path) -> None:
    context = VaultContext(app_data_dir=tmp_path, file_service=object())
    service = VaultFileService(context)

    service._require_file_service = lambda: SimpleNamespace(  # type: ignore[method-assign]
        get_file_reference_with_blobs=lambda ref_id: SimpleNamespace(
            id=ref_id,
            is_folder=False,
            file_entry=SimpleNamespace(metadata_json='{"mime_type":"text/plain","size_bytes":5}'),
        )
    )

    metadata = service.get_file_reference_metadata(7)

    assert metadata == {"mime_type": "text/plain", "size_bytes": 5}


def test_get_file_reference_metadata_returns_empty_when_missing_metadata(tmp_path: Path) -> None:
    context = VaultContext(app_data_dir=tmp_path, file_service=object())
    service = VaultFileService(context)

    service._require_file_service = lambda: SimpleNamespace(  # type: ignore[method-assign]
        get_file_reference_with_blobs=lambda ref_id: SimpleNamespace(
            id=ref_id,
            is_folder=False,
            file_entry=SimpleNamespace(metadata_json=None),
        )
    )

    assert service.get_file_reference_metadata(3) == {}


def test_get_file_reference_metadata_raises_for_folder(tmp_path: Path) -> None:
    context = VaultContext(app_data_dir=tmp_path, file_service=object())
    service = VaultFileService(context)

    service._require_file_service = lambda: SimpleNamespace(  # type: ignore[method-assign]
        get_file_reference_with_blobs=lambda ref_id: SimpleNamespace(
            id=ref_id,
            is_folder=True,
            file_entry=None,
        )
    )

    with pytest.raises(IsADirectoryError, match="is a folder"):
        service.get_file_reference_metadata(9)


def test_get_file_reference_metadata_raises_for_missing_reference(tmp_path: Path) -> None:
    context = VaultContext(app_data_dir=tmp_path, file_service=object())
    service = VaultFileService(context)

    service._require_file_service = lambda: SimpleNamespace(  # type: ignore[method-assign]
        get_file_reference_with_blobs=lambda ref_id: None
    )

    with pytest.raises(FileNotFoundError, match="File reference not found"):
        service.get_file_reference_metadata(11)
