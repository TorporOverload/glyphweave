import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.services.models import AddFileResult, SearchPage, SearchResult, VaultContext
from app.services.vault_files.vault_file_service import VaultFileService


class _MasterKey:
    def __init__(self, value: bytes) -> None:
        self._value = value

    def view(self):
        return memoryview(self._value)


def test_add_file_with_duplicate_content_hash_reuses_existing_blob(
    monkeypatch, tmp_path: Path
) -> None:
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

    def mock_add_file(
        context,
        *,
        file_service,
        folder_service,
        encryption_service,
        indexing_service,
        event_emitter,
        source,
        dest_name,
        dest_parent_virtual_path,
    ):
        return AddFileResult(
            file_name="report.txt",
            deduplicated=True,
            file_id=None,
            original_size=5,
            encrypted_size=10,
            blob_count=0,
            indexed=True,
        )

    monkeypatch.setattr(
        "app.services.vault_files.commands.add_file_to_vault",
        mock_add_file,
    )

    result = service.add_file(source)

    assert result.deduplicated is True
    assert result.blob_count == 0
    assert result.indexed is True
    assert result.file_id is None


def test_unmount_unlocked_when_mounted(monkeypatch, tmp_path: Path) -> None:
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
    unmount_calls: list[int] = []

    class MockMounts:
        def is_mounted(self, file_ref_id: int) -> bool:
            return file_ref_id == 42

        def unmount(self, file_ref_id: int, background: bool = False) -> bool:
            unmount_calls.append(file_ref_id)
            return True

    context.mounts = MockMounts()

    from app.services.vault_files import access

    result = access.unmount_unlocked(service, 42)

    assert 42 in unmount_calls
    assert "Unmount started" in result or "background" in result.lower()


def test_unmount_unlocked_when_not_mounted_raises(tmp_path: Path) -> None:
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

    class MockMounts:
        def is_mounted(self, file_ref_id: int) -> bool:
            return False

        def unmount(self, file_ref_id: int, background: bool = False) -> bool:
            return False

    context.mounts = MockMounts()

    from app.services.vault_files import access

    with pytest.raises(FileNotFoundError, match="no longer unlocked"):
        access.unmount_unlocked(service, 99)


def test_get_file_reference_metadata_with_empty_json_string(
    tmp_path: Path,
) -> None:
    context = VaultContext(app_data_dir=tmp_path, file_service=object())
    service = VaultFileService(context)

    service._require_file_service = lambda: MagicMock(
        get_file_reference_with_blobs=lambda ref_id: SimpleNamespace(
            id=ref_id,
            is_folder=False,
            file_entry=SimpleNamespace(metadata_json=""),
        )
    )

    metadata = service.get_file_reference_metadata(5)

    assert metadata == {}


def test_get_file_reference_metadata_with_invalid_json(
    tmp_path: Path,
) -> None:
    context = VaultContext(app_data_dir=tmp_path, file_service=object())
    service = VaultFileService(context)

    service._require_file_service = lambda: MagicMock(
        get_file_reference_with_blobs=lambda ref_id: SimpleNamespace(
            id=ref_id,
            is_folder=False,
            file_entry=SimpleNamespace(metadata_json="{invalid}"),
        )
    )

    with pytest.raises(json.JSONDecodeError):
        service.get_file_reference_metadata(6)


def test_get_file_reference_metadata_with_deeply_nested_json(
    tmp_path: Path,
) -> None:
    context = VaultContext(app_data_dir=tmp_path, file_service=object())
    service = VaultFileService(context)

    nested_data = {"level1": {"level2": {"level3": {"value": 123}}}}
    service._require_file_service = lambda: MagicMock(
        get_file_reference_with_blobs=lambda ref_id: SimpleNamespace(
            id=ref_id,
            is_folder=False,
            file_entry=SimpleNamespace(metadata_json=json.dumps(nested_data)),
        )
    )

    metadata = service.get_file_reference_metadata(7)

    assert metadata == nested_data


def test_get_file_reference_metadata_with_special_characters_in_json(
    tmp_path: Path,
) -> None:
    context = VaultContext(app_data_dir=tmp_path, file_service=object())
    service = VaultFileService(context)

    special_data = {"name": "file.txt", "chars": '"\n\t\\'}
    service._require_file_service = lambda: MagicMock(
        get_file_reference_with_blobs=lambda ref_id: SimpleNamespace(
            id=ref_id,
            is_folder=False,
            file_entry=SimpleNamespace(metadata_json=json.dumps(special_data)),
        )
    )

    metadata = service.get_file_reference_metadata(8)

    assert metadata == special_data


def test_search_pagination_exact_boundary(monkeypatch, tmp_path: Path) -> None:
    context = VaultContext(
        app_data_dir=tmp_path,
        session_factory=object(),
    )
    service = VaultFileService(context)

    results = [
        SearchResult(file_ref_id=1, file_name="file_a.txt", virtual_path="/file_a.txt", snippet="", rank=1.0),
        SearchResult(file_ref_id=2, file_name="file_b.txt", virtual_path="/file_b.txt", snippet="", rank=1.0),
        SearchResult(file_ref_id=3, file_name="file_c.txt", virtual_path="/file_c.txt", snippet="", rank=1.0),
    ]

    monkeypatch.setattr(
        "app.services.vault_files.queries.search_file_references",
        lambda session, query, limit: [(r.file_ref_id, r.file_name, r.virtual_path, r.rank) for r in results[:limit]],
    )
    monkeypatch.setattr(
        "app.services.vault_files.queries.search_content",
        lambda session, query, limit: [],
    )

    mock_session = MagicMock()
    monkeypatch.setattr(
        "app.services.vault_files.queries.session_scope",
        lambda *args, **kwargs: __import__("contextlib").nullcontext(mock_session),
    )

    page = service.search_page("file", limit=2, offset=0)

    assert len(page.results) == 2
    assert page.has_more is True


def test_search_pagination_offset_beyond_results(monkeypatch, tmp_path: Path) -> None:
    context = VaultContext(
        app_data_dir=tmp_path,
        session_factory=object(),
    )
    service = VaultFileService(context)

    monkeypatch.setattr(
        "app.services.vault_files.queries.search_file_references",
        lambda session, query, limit: [(1, "file.txt", "/file.txt", 1.0)],
    )
    monkeypatch.setattr(
        "app.services.vault_files.queries.search_content",
        lambda session, query, limit: [],
    )

    mock_session = MagicMock()
    monkeypatch.setattr(
        "app.services.vault_files.queries.session_scope",
        lambda *args, **kwargs: __import__("contextlib").nullcontext(mock_session),
    )

    page = service.search_page("file", limit=10, offset=100)

    assert page.results == []
    assert page.has_more is False


def test_search_pagination_zero_limit(monkeypatch, tmp_path: Path) -> None:
    context = VaultContext(
        app_data_dir=tmp_path,
        session_factory=object(),
    )
    service = VaultFileService(context)

    monkeypatch.setattr(
        "app.services.vault_files.queries.search_file_references",
        lambda session, query, limit: [(1, "file.txt", "/file.txt", 1.0)],
    )
    monkeypatch.setattr(
        "app.services.vault_files.queries.search_content",
        lambda session, query, limit: [],
    )

    mock_session = MagicMock()
    monkeypatch.setattr(
        "app.services.vault_files.queries.session_scope",
        lambda *args, **kwargs: __import__("contextlib").nullcontext(mock_session),
    )

    page = service.search_page("file", limit=0, offset=0)

    assert page.results == []
    assert page.has_more is True


def test_search_empty_query_returns_empty_page(tmp_path: Path) -> None:
    context = VaultContext(
        app_data_dir=tmp_path,
        session_factory=object(),
    )
    service = VaultFileService(context)

    page = service.search_page("   ", limit=10, offset=0)

    assert page.results == []
    assert page.has_more is False


def test_select_supported_reference_name_all_unsupported(tmp_path: Path) -> None:
    entry = SimpleNamespace(
        references=[
            SimpleNamespace(name="file.xyz"),
            SimpleNamespace(name="document.abc"),
        ]
    )

    result = VaultFileService._select_supported_reference_name(entry)

    assert result is None


def test_search_pagination_with_exact_fit(monkeypatch, tmp_path: Path) -> None:
    context = VaultContext(
        app_data_dir=tmp_path,
        session_factory=object(),
    )
    service = VaultFileService(context)

    results = [
        SearchResult(file_ref_id=1, file_name="file1.txt", virtual_path="/file1.txt", snippet="", rank=1.0),
        SearchResult(file_ref_id=2, file_name="file2.txt", virtual_path="/file2.txt", snippet="", rank=1.0),
    ]

    monkeypatch.setattr(
        "app.services.vault_files.queries.search_file_references",
        lambda session, query, limit: [(r.file_ref_id, r.file_name, r.virtual_path, r.rank) for r in results[:limit]],
    )
    monkeypatch.setattr(
        "app.services.vault_files.queries.search_content",
        lambda session, query, limit: [],
    )

    mock_session = MagicMock()
    monkeypatch.setattr(
        "app.services.vault_files.queries.session_scope",
        lambda *args, **kwargs: __import__("contextlib").nullcontext(mock_session),
    )

    page = service.search_page("file", limit=2, offset=0)

    assert len(page.results) == 2
    assert page.has_more is False