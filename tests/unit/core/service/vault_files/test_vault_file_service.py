from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.common.paths.runtime_layout import runtime_cache_dir
from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.model.sync_conflict import SyncConflict
from app.infrastructure.persistence.db.service.folder_service import FolderService
from app.infrastructure.persistence.db.service.session import session_scope
from app.services.models import AddFileResult, VaultContext
from app.services.vault_files.vault_file_service import VaultFileService


class _MasterKey:
    def __init__(self, value: bytes) -> None:
        self._value = value

    def view(self) -> memoryview:
        return memoryview(self._value)


def test_build_indexing_service_returns_none_when_context_incomplete(
    tmp_path: Path,
) -> None:
    service = VaultFileService(VaultContext(app_data_dir=tmp_path))

    assert service._build_indexing_service() is None


def test_cleanup_is_safe_when_runtime_services_are_not_initialized(
    tmp_path: Path,
) -> None:
    service = VaultFileService(VaultContext(app_data_dir=tmp_path))

    service.cleanup()


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


def test_add_file_passes_indexing_service_to_import(
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
    captured = {}

    monkeypatch.setattr(
        "app.services.vault_files.commands.add_file_to_vault",
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
        "app.services.vault_files.queries.session_scope",
        lambda *args, **kwargs: __import__("contextlib").nullcontext(session),
    )
    monkeypatch.setattr(
        "app.services.vault_files.queries.get_retriable_extractions",
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


def test_restore_sync_conflict_delegates_to_commands(tmp_path: Path) -> None:
    context = VaultContext(app_data_dir=tmp_path)
    service = VaultFileService(context)
    captured = {}

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        "app.services.vault_files.commands.restore_sync_conflict",
        lambda svc,
        conflict_id,
        destination_folder_virtual_path,
        new_name: captured.update(
            {
                "service": svc,
                "conflict_id": conflict_id,
                "destination": destination_folder_virtual_path,
                "new_name": new_name,
            }
        )
        or SimpleNamespace(virtual_path="/restored.txt"),
    )

    try:
        result = service.restore_sync_conflict(
            "conflict-1",
            destination_folder_virtual_path="/",
            new_name="restored.txt",
        )
    finally:
        monkeypatch.undo()

    assert result.virtual_path == "/restored.txt"
    assert captured["service"] is service
    assert captured["conflict_id"] == "conflict-1"
    assert captured["destination"] == "/"
    assert captured["new_name"] == "restored.txt"


def test_delete_conflicted_folder_emits_resolution_for_descendant_conflicts(
    tmp_path: Path,
) -> None:
    service, session_factory = _build_folder_service(tmp_path)
    conflict_folder_id, archived_folder_id, child_file_id = _seed_conflict_tree(
        session_factory
    )
    emitted: list[tuple[str, str, str]] = []
    deleted: list[str] = []

    class _Emitter:
        def emit_folder_conflict_resolved(
            self,
            *,
            conflict_id: str,
            node_id: str,
            resolution_status: str,
            resolution_reason: str,
        ) -> SimpleNamespace:
            emitted.append((conflict_id, node_id, resolution_status))
            return SimpleNamespace(event_id=f"{conflict_id}:{resolution_status}")

        def emit_file_conflict_resolved(
            self,
            *,
            conflict_id: str,
            node_id: str,
            resolution_status: str,
            resolution_reason: str,
        ) -> SimpleNamespace:
            emitted.append((conflict_id, node_id, resolution_status))
            return SimpleNamespace(event_id=f"{conflict_id}:{resolution_status}")

    service._build_event_emitter = lambda: _Emitter()  # type: ignore[method-assign]
    service._emit_delete_event = (  # type: ignore[method-assign]
        lambda entry, file_id=None: deleted.append(entry.node_id)
    )

    deleted_count = service.delete_entries(["/.glyphweave_conflicts/archive"])

    assert deleted_count == 1
    assert deleted == ["folder-node"]
    assert emitted == [
        ("conflict-folder", "folder-node", "deleted"),
        ("conflict-child", "child-node", "deleted"),
    ]
    with session_scope(session_factory, commit=False) as session:
        remaining = session.scalars(select(FileReference)).all()
        conflicts = session.scalars(
            select(SyncConflict).order_by(SyncConflict.conflict_id)
        ).all()
        assert [ref.id for ref in remaining] == [conflict_folder_id]
        assert session.get(FileReference, archived_folder_id) is None
        assert session.get(FileReference, child_file_id) is None
        assert [conflict.status for conflict in conflicts] == ["deleted", "deleted"]


def test_restore_conflicted_folder_resolves_descendant_conflicts(
    tmp_path: Path,
) -> None:
    service, session_factory = _build_folder_service(tmp_path)
    _seed_conflict_tree(session_factory)
    move_events: list[tuple[str, int | None, str]] = []
    emitted: list[tuple[str, str, str]] = []

    class _Emitter:
        def emit_folder_create(self, folder_ref) -> None:
            del folder_ref

        def emit_folder_conflict_resolved(
            self,
            *,
            conflict_id: str,
            node_id: str,
            resolution_status: str,
            resolution_reason: str,
        ) -> SimpleNamespace:
            emitted.append((conflict_id, node_id, resolution_status))
            return SimpleNamespace(event_id=f"{conflict_id}:{resolution_status}")

        def emit_file_conflict_resolved(
            self,
            *,
            conflict_id: str,
            node_id: str,
            resolution_status: str,
            resolution_reason: str,
        ) -> SimpleNamespace:
            emitted.append((conflict_id, node_id, resolution_status))
            return SimpleNamespace(event_id=f"{conflict_id}:{resolution_status}")

    service._build_event_emitter = lambda: _Emitter()  # type: ignore[method-assign]
    service._emit_move_event = (  # type: ignore[method-assign]
        lambda entry, destination_parent_id, new_name: move_events.append(
            (entry.node_id, destination_parent_id, new_name)
        )
    )

    restored = service.restore_sync_conflict(
        "conflict-folder",
        destination_folder_virtual_path="/restored",
    )

    assert restored.virtual_path == "/restored/archive"
    assert emitted == [
        ("conflict-folder", "folder-node", "resolved"),
        ("conflict-child", "child-node", "resolved"),
    ]
    assert move_events == [("folder-node", restored.parent_id, "archive")]
    with session_scope(session_factory, commit=False) as session:
        child = session.scalar(
            select(FileReference).where(FileReference.node_id == "child-node")
        )
        conflicts = session.scalars(
            select(SyncConflict).order_by(SyncConflict.conflict_id)
        ).all()
        assert child is not None
        assert child.virtual_path == "/restored/archive/child.txt"
        assert [conflict.status for conflict in conflicts] == ["resolved", "resolved"]


def test_restore_conflicted_folder_rejects_descendant_destination_without_side_effects(
    tmp_path: Path,
) -> None:
    service, session_factory = _build_folder_service(tmp_path)
    _seed_conflict_tree(session_factory)

    with pytest.raises(ValueError, match="Cannot restore a folder into itself"):
        service.restore_sync_conflict(
            "conflict-folder",
            destination_folder_virtual_path="/.glyphweave_conflicts/archive/nested",
        )

    with session_scope(session_factory, commit=False) as session:
        paths = session.scalars(
            select(FileReference.virtual_path).order_by(FileReference.virtual_path)
        ).all()
        assert paths == [
            "/.glyphweave_conflicts",
            "/.glyphweave_conflicts/archive",
            "/.glyphweave_conflicts/archive/child.txt",
        ]


def test_restore_conflicted_file_resolves_all_active_conflicts_for_node(
    tmp_path: Path,
) -> None:
    service, session_factory = _build_folder_service(tmp_path)
    _seed_file_with_multiple_conflicts(session_factory)
    emitted: list[tuple[str, str, str]] = []
    move_events: list[tuple[str, int | None, str]] = []

    class _Emitter:
        def emit_folder_create(self, folder_ref) -> None:
            del folder_ref

        def emit_file_conflict_resolved(
            self,
            *,
            conflict_id: str,
            node_id: str,
            resolution_status: str,
            resolution_reason: str,
        ) -> SimpleNamespace:
            emitted.append((conflict_id, node_id, resolution_status))
            return SimpleNamespace(event_id=f"{conflict_id}:{resolution_status}")

    service._build_event_emitter = lambda: _Emitter()  # type: ignore[method-assign]
    service._emit_move_event = (  # type: ignore[method-assign]
        lambda entry, destination_parent_id, new_name: move_events.append(
            (entry.node_id, destination_parent_id, new_name)
        )
    )

    restored = service.restore_sync_conflict(
        "conflict-file-a",
        destination_folder_virtual_path="/restored",
    )

    assert restored.virtual_path == "/restored/archived.txt"
    assert emitted == [
        ("conflict-file-a", "file-node", "resolved"),
        ("conflict-file-b", "file-node", "resolved"),
    ]
    assert move_events == [("file-node", restored.parent_id, "archived.txt")]
    with session_scope(session_factory, commit=False) as session:
        conflicts = session.scalars(
            select(SyncConflict).order_by(SyncConflict.conflict_id)
        ).all()
        assert [conflict.status for conflict in conflicts] == ["resolved", "resolved"]


def test_delete_conflicted_folder_escapes_like_wildcards_in_virtual_path(
    tmp_path: Path,
) -> None:
    service, session_factory = _build_folder_service(tmp_path)
    _seed_wildcard_conflict_tree(session_factory)
    service._build_event_emitter = lambda: None  # type: ignore[method-assign]

    deleted_count = service.delete_entries(["/.glyphweave_conflicts/arch_"])

    assert deleted_count == 1
    with session_scope(session_factory, commit=False) as session:
        conflicts = session.scalars(
            select(SyncConflict).order_by(SyncConflict.conflict_id)
        ).all()
        remaining_paths = session.scalars(
            select(FileReference.virtual_path).order_by(FileReference.virtual_path)
        ).all()
        statuses = {conflict.conflict_id: conflict.status for conflict in conflicts}
        assert statuses == {
            "conflict-child-a": "deleted",
            "conflict-child-b": "active",
            "conflict-folder-a": "deleted",
        }
        assert remaining_paths == [
            "/.glyphweave_conflicts",
            "/.glyphweave_conflicts/archX",
            "/.glyphweave_conflicts/archX/b.txt",
        ]


def test_reindex_pending_delegates_supported_name_selection(tmp_path: Path) -> None:
    entry = SimpleNamespace(
        references=[
            SimpleNamespace(name="photo.png"),
            SimpleNamespace(name="Þ‹Þ¨ÞˆÞ¬Þ€Þ¨.txt"),
        ]
    )

    assert (
        VaultFileService._select_supported_reference_name(entry) == "Þ‹Þ¨ÞˆÞ¬Þ€Þ¨.txt"
    )


def test_get_file_reference_metadata_returns_parsed_metadata(tmp_path: Path) -> None:
    context = VaultContext(app_data_dir=tmp_path, file_service=object())
    service = VaultFileService(context)

    service._require_file_service = lambda: SimpleNamespace(  # type: ignore[method-assign]
        get_file_reference_with_blobs=lambda ref_id: SimpleNamespace(
            id=ref_id,
            is_folder=False,
            file_entry=SimpleNamespace(
                metadata_json='{"mime_type":"text/plain","size_bytes":5}'
            ),
        )
    )

    metadata = service.get_file_reference_metadata(7)

    assert metadata == {"mime_type": "text/plain", "size_bytes": 5}


def test_get_file_reference_metadata_returns_empty_when_missing_metadata(
    tmp_path: Path,
) -> None:
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


def test_get_file_reference_metadata_raises_for_missing_reference(
    tmp_path: Path,
) -> None:
    context = VaultContext(app_data_dir=tmp_path, file_service=object())
    service = VaultFileService(context)

    service._require_file_service = lambda: SimpleNamespace(  # type: ignore[method-assign]
        get_file_reference_with_blobs=lambda ref_id: None
    )

    with pytest.raises(FileNotFoundError, match="File reference not found"):
        service.get_file_reference_metadata(11)


def _build_folder_service(tmp_path: Path) -> tuple[VaultFileService, sessionmaker]:
    vault_path = tmp_path / "vault"
    vault_path.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{tmp_path / 'vault_files.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    context = VaultContext(
        app_data_dir=tmp_path,
        session_factory=session_factory,
        folder_service=FolderService(session_factory, vault_path),
    )
    return VaultFileService(context), session_factory


def _seed_conflict_tree(session_factory: sessionmaker) -> tuple[int, int, int]:
    with session_scope(session_factory) as session:
        conflict_root = FileReference(
            node_id="conflict-root",
            name=".glyphweave_conflicts",
            is_folder=True,
            file_entry_id=None,
        )
        session.add(conflict_root)
        session.flush()

        archived_folder = FileReference(
            node_id="folder-node",
            parent=conflict_root,
            name="archive",
            is_folder=True,
            file_entry_id=None,
        )
        session.add(archived_folder)
        session.flush()

        child_file = FileReference(
            node_id="child-node",
            parent=archived_folder,
            name="child.txt",
            is_folder=False,
            file_entry_id=None,
        )
        session.add(child_file)
        session.flush()

        session.add_all(
            [
                SyncConflict(
                    conflict_id="conflict-folder",
                    node_id="folder-node",
                    node_kind="folder",
                    archived_file_ref_id=archived_folder.id,
                    file_entry_id=None,
                    archived_name=archived_folder.name,
                    archived_virtual_path=archived_folder.virtual_path,
                    reason_code="deleted_parent_folder_move",
                    reason_text="Folder conflict",
                    trigger_event_id="evt-folder",
                    trigger_event_hash=None,
                    trigger_event_type="folder_move",
                    origin_device_id="device-a",
                    status="active",
                ),
                SyncConflict(
                    conflict_id="conflict-child",
                    node_id="child-node",
                    node_kind="file",
                    archived_file_ref_id=child_file.id,
                    file_entry_id=None,
                    archived_name=child_file.name,
                    archived_virtual_path=child_file.virtual_path,
                    reason_code="deleted_parent_move",
                    reason_text="Child conflict",
                    trigger_event_id="evt-child",
                    trigger_event_hash=None,
                    trigger_event_type="file_move",
                    origin_device_id="device-a",
                    status="active",
                ),
            ]
        )
        session.flush()
        return conflict_root.id, archived_folder.id, child_file.id


def _seed_file_with_multiple_conflicts(session_factory: sessionmaker) -> None:
    with session_scope(session_factory) as session:
        conflict_root = FileReference(
            node_id="conflict-root",
            name=".glyphweave_conflicts",
            is_folder=True,
            file_entry_id=None,
        )
        session.add(conflict_root)
        session.flush()

        archived_file = FileReference(
            node_id="file-node",
            parent=conflict_root,
            name="archived.txt",
            is_folder=False,
            file_entry_id=None,
        )
        session.add(archived_file)
        session.flush()

        session.add_all(
            [
                SyncConflict(
                    conflict_id="conflict-file-a",
                    node_id="file-node",
                    node_kind="file",
                    archived_file_ref_id=archived_file.id,
                    file_entry_id=None,
                    archived_name=archived_file.name,
                    archived_virtual_path=archived_file.virtual_path,
                    reason_code="deleted_parent_move",
                    reason_text="File conflict A",
                    trigger_event_id="evt-file-a",
                    trigger_event_hash=None,
                    trigger_event_type="file_move",
                    origin_device_id="device-a",
                    status="active",
                ),
                SyncConflict(
                    conflict_id="conflict-file-b",
                    node_id="file-node",
                    node_kind="file",
                    archived_file_ref_id=archived_file.id,
                    file_entry_id=None,
                    archived_name=archived_file.name,
                    archived_virtual_path=archived_file.virtual_path,
                    reason_code="deleted_parent_add",
                    reason_text="File conflict B",
                    trigger_event_id="evt-file-b",
                    trigger_event_hash=None,
                    trigger_event_type="file_add",
                    origin_device_id="device-a",
                    status="active",
                ),
            ]
        )
        session.flush()


def _seed_wildcard_conflict_tree(session_factory: sessionmaker) -> None:
    with session_scope(session_factory) as session:
        conflict_root = FileReference(
            node_id="conflict-root",
            name=".glyphweave_conflicts",
            is_folder=True,
            file_entry_id=None,
        )
        session.add(conflict_root)
        session.flush()

        archived_folder = FileReference(
            node_id="folder-a",
            parent=conflict_root,
            name="arch_",
            is_folder=True,
            file_entry_id=None,
        )
        sibling_folder = FileReference(
            node_id="folder-b",
            parent=conflict_root,
            name="archX",
            is_folder=True,
            file_entry_id=None,
        )
        session.add_all([archived_folder, sibling_folder])
        session.flush()

        archived_child = FileReference(
            node_id="child-a",
            parent=archived_folder,
            name="a.txt",
            is_folder=False,
            file_entry_id=None,
        )
        sibling_child = FileReference(
            node_id="child-b",
            parent=sibling_folder,
            name="b.txt",
            is_folder=False,
            file_entry_id=None,
        )
        session.add_all([archived_child, sibling_child])
        session.flush()

        session.add_all(
            [
                SyncConflict(
                    conflict_id="conflict-folder-a",
                    node_id="folder-a",
                    node_kind="folder",
                    archived_file_ref_id=archived_folder.id,
                    file_entry_id=None,
                    archived_name=archived_folder.name,
                    archived_virtual_path=archived_folder.virtual_path,
                    reason_code="deleted_parent_folder_move",
                    reason_text="Folder conflict",
                    trigger_event_id="evt-folder-a",
                    trigger_event_hash=None,
                    trigger_event_type="folder_move",
                    origin_device_id="device-a",
                    status="active",
                ),
                SyncConflict(
                    conflict_id="conflict-child-a",
                    node_id="child-a",
                    node_kind="file",
                    archived_file_ref_id=archived_child.id,
                    file_entry_id=None,
                    archived_name=archived_child.name,
                    archived_virtual_path=archived_child.virtual_path,
                    reason_code="deleted_parent_move",
                    reason_text="Child conflict A",
                    trigger_event_id="evt-child-a",
                    trigger_event_hash=None,
                    trigger_event_type="file_move",
                    origin_device_id="device-a",
                    status="active",
                ),
                SyncConflict(
                    conflict_id="conflict-child-b",
                    node_id="child-b",
                    node_kind="file",
                    archived_file_ref_id=sibling_child.id,
                    file_entry_id=None,
                    archived_name=sibling_child.name,
                    archived_virtual_path=sibling_child.virtual_path,
                    reason_code="deleted_parent_move",
                    reason_text="Child conflict B",
                    trigger_event_id="evt-child-b",
                    trigger_event_hash=None,
                    trigger_event_type="file_move",
                    origin_device_id="device-a",
                    status="active",
                ),
            ]
        )
        session.flush()
