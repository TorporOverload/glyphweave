from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.database.model.extraction_status import ExtractionStatus
from app.core.service.models import VaultContext
from app.core.service.vault_file_import import add_file
from app.core.vault_layout import resolve_blob_path, writable_blobs_dir


class _MasterKey:
    def __init__(self, value: bytes) -> None:
        self._value = value

    def get(self) -> bytes:
        return self._value

    def view(self) -> memoryview:
        return memoryview(self._value)


class _FakeEncryptionService:
    def __init__(self, blob_ids: list[str], *, error: Exception | None = None) -> None:
        self.blob_ids = blob_ids
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def encrypt_file(self, **kwargs: Any) -> list[str]:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error

        vault_path = kwargs["vault_path"]
        blob_store = writable_blobs_dir(vault_path)
        for idx, blob_id in enumerate(self.blob_ids, start=1):
            (blob_store / blob_id).write_bytes(b"x" * idx)
        return self.blob_ids


class _FakeFileService:
    def __init__(self, existing_entry: Any = None) -> None:
        self.existing_entry = existing_entry
        self.find_hashes: list[str] = []
        self.created_entries: list[dict[str, Any]] = []
        self.created_refs: list[dict[str, Any]] = []

    def find_by_content_hash(self, content_hash: str) -> Any:
        self.find_hashes.append(content_hash)
        return self.existing_entry

    def create_file_reference(self, **kwargs: Any) -> Any:
        self.created_refs.append(kwargs)
        return SimpleNamespace(id=10, **kwargs)

    def create_file_entry_with_blobs(self, **kwargs: Any) -> Any:
        self.created_entries.append(kwargs)
        return SimpleNamespace(id=99, **kwargs)


class _FakeFolderService:
    def __init__(self) -> None:
        self.children: dict[tuple[int | None, str], Any] = {}
        self.created_folders: list[dict[str, Any]] = []
        self._next_id = 1000

    def get_child_by_name(self, parent_id: int | None, name: str) -> Any:
        return self.children.get((parent_id, name))

    def create_folder(self, name: str, parent_id: int | None) -> Any:
        folder = SimpleNamespace(id=self._next_id, name=name, is_folder=True)
        self._next_id += 1
        self.children[(parent_id, name)] = folder
        self.created_folders.append(
            {"id": folder.id, "name": name, "parent_id": parent_id}
        )
        return folder


class _FakeIndexingService:
    def __init__(self, result: bool) -> None:
        self.result = result
        self.calls: list[tuple[int, Path, str]] = []

    def index_source_file(
        self,
        file_entry_id: int,
        source_path: Path,
        filename: str,
    ) -> bool:
        self.calls.append((file_entry_id, source_path, filename))
        return self.result


def _build_context(tmp_path: Path) -> VaultContext:
    vault_path = tmp_path / "vault"
    vault_path.mkdir()
    return VaultContext(
        app_data_dir=tmp_path,
        vault_id="vault-1",
        vault_path=vault_path,
        master_key=_MasterKey(b"k" * 32),
    )


def test_add_file_reuses_existing_content_hash(tmp_path: Path) -> None:
    source = tmp_path / "report.txt"
    source.write_text("hello", encoding="utf-8")
    existing_entry = SimpleNamespace(
        id=7,
        original_size_bytes=5,
        encrypted_size_bytes=12,
        text_extraction_status=ExtractionStatus.DONE.value,
    )
    context = _build_context(tmp_path)
    file_service = _FakeFileService(existing_entry=existing_entry)
    encryption_service = _FakeEncryptionService(["blob-1.enc"])

    result = add_file(
        context,
        file_service=file_service,
        encryption_service=encryption_service,
        source=source,
        dest_name="copy.txt",
    )

    assert result.deduplicated is True
    assert result.file_name == "copy.txt"
    assert result.file_id is None
    assert result.original_size == 5
    assert result.encrypted_size == 12
    assert result.blob_count == 0
    assert result.indexed is True
    assert file_service.created_refs == [
        {"name": "copy.txt", "parent_id": None, "file_entry_id": 7}
    ]
    assert file_service.created_entries == []
    assert encryption_service.calls == []


def test_add_file_encrypts_and_creates_new_entry(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("hello", encoding="utf-8")
    context = _build_context(tmp_path)
    file_service = _FakeFileService()
    encryption_service = _FakeEncryptionService(["blob-1.enc", "blob-2.enc"])

    result = add_file(
        context,
        file_service=file_service,
        encryption_service=encryption_service,
        source=source,
    )

    assert result.deduplicated is False
    assert result.file_name == "notes.txt"
    assert result.file_id is not None
    assert result.original_size == 5
    assert result.encrypted_size == 3
    assert result.blob_count == 2
    assert result.indexed is False
    assert len(file_service.created_entries) == 1
    assert file_service.created_entries[0]["blob_ids"] == ["blob-1.enc", "blob-2.enc"]
    assert file_service.created_refs == [
        {"name": "notes.txt", "parent_id": None, "file_entry_id": 99}
    ]


def test_add_file_cleans_partial_blobs_on_entry_creation_failure(
    tmp_path: Path,
) -> None:
    source = tmp_path / "bad.txt"
    source.write_text("hello", encoding="utf-8")
    context = _build_context(tmp_path)
    file_service = _FakeFileService()
    encryption_service = _FakeEncryptionService(["blob-1.enc", "blob-2.enc"])

    def _raise_on_entry(**kwargs: Any) -> Any:
        raise RuntimeError("db insert failed")

    file_service.create_file_entry_with_blobs = _raise_on_entry  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="db insert failed"):
        add_file(
            context,
            file_service=file_service,
            encryption_service=encryption_service,
            source=source,
        )

    assert context.vault_path is not None
    assert not resolve_blob_path(context.vault_path, "blob-1.enc").exists()
    assert not resolve_blob_path(context.vault_path, "blob-2.enc").exists()


def test_add_file_creates_nested_destination_folders(tmp_path: Path) -> None:
    source = tmp_path / "nested.txt"
    source.write_text("hello", encoding="utf-8")

    context = _build_context(tmp_path)
    file_service = _FakeFileService()
    folder_service = _FakeFolderService()
    encryption_service = _FakeEncryptionService(["blob-1.enc"])

    result = add_file(
        context,
        file_service=file_service,
        folder_service=folder_service,
        encryption_service=encryption_service,
        source=source,
        dest_name="nested.txt",
        dest_parent_virtual_path="/docs/2026/march",
    )

    assert result.file_name == "nested.txt"
    assert [folder["name"] for folder in folder_service.created_folders] == [
        "docs",
        "2026",
        "march",
    ]
    march_folder_id = folder_service.created_folders[-1]["id"]
    assert file_service.created_refs == [
        {"name": "nested.txt", "parent_id": march_folder_id, "file_entry_id": 99}
    ]


def test_add_file_rejects_destination_path_when_segment_is_file(tmp_path: Path) -> None:
    source = tmp_path / "nested.txt"
    source.write_text("hello", encoding="utf-8")

    context = _build_context(tmp_path)
    file_service = _FakeFileService()
    folder_service = _FakeFolderService()
    encryption_service = _FakeEncryptionService(["blob-1.enc"])

    folder_service.children[(None, "docs")] = SimpleNamespace(
        id=42,
        name="docs",
        is_folder=False,
    )

    with pytest.raises(NotADirectoryError, match="/docs"):
        add_file(
            context,
            file_service=file_service,
            folder_service=folder_service,
            encryption_service=encryption_service,
            source=source,
            dest_name="nested.txt",
            dest_parent_virtual_path="/docs/2026",
        )


def test_add_file_invokes_indexing_service_after_new_import(tmp_path: Path) -> None:
    source = tmp_path / "report.txt"
    source.write_text("hello", encoding="utf-8")
    context = _build_context(tmp_path)
    file_service = _FakeFileService()
    encryption_service = _FakeEncryptionService(["blob-1.enc"])
    indexing_service = _FakeIndexingService(True)

    result = add_file(
        context,
        file_service=file_service,
        encryption_service=encryption_service,
        indexing_service=indexing_service,
        source=source,
    )

    assert result.indexed is True
    assert len(indexing_service.calls) == 1
    assert indexing_service.calls[0] == (99, source, "report.txt")


def test_add_file_does_not_fail_when_indexing_returns_false(tmp_path: Path) -> None:
    source = tmp_path / "report.txt"
    source.write_text("hello", encoding="utf-8")
    context = _build_context(tmp_path)
    file_service = _FakeFileService()
    encryption_service = _FakeEncryptionService(["blob-1.enc"])
    indexing_service = _FakeIndexingService(False)

    result = add_file(
        context,
        file_service=file_service,
        encryption_service=encryption_service,
        indexing_service=indexing_service,
        source=source,
    )

    assert result.deduplicated is False
    assert result.file_name == "report.txt"
    assert result.indexed is False
