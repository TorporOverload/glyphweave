from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.file_entry import FileEntry
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.model.processed_event import ProcessedEvent
from app.infrastructure.persistence.db.model.sync_conflict import SyncConflict
from app.infrastructure.persistence.db.model.sync_node_state import SyncNodeState
from app.infrastructure.persistence.db.model.sync_tombstone import SyncTombstone
from app.infrastructure.persistence.db.service.sync_conflict_service import (
    upsert_sync_conflict,
)
from app.services.sync.event_processor import EventProcessor
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import (
    DiscoveredEvent,
    HybridLogicalClock,
    ProcessingStatus,
    VaultEvent,
)


def _build_processor(tmp_path):
    db_path = tmp_path / "event_processor.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return EventProcessor(session_factory), session_factory


_logical_seq = [0]


def _event(event_id: str, event_type: EventType, payload: dict) -> VaultEvent:
    logical = _logical_seq[0]
    _logical_seq[0] += 1
    return VaultEvent(
        event_id=event_id,
        type=event_type,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=1000, logical=logical, device_id="device-a"),
        payload=payload,
        parents=[],
        event_hash="hash-" + event_id,
    )


def test_process_folder_create_and_file_add(tmp_path) -> None:
    processor, session_factory = _build_processor(tmp_path)
    folder_event = _event(
        "evt-folder",
        EventType.FOLDER_CREATE,
        {"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
    )
    file_event = _event(
        "evt-file",
        EventType.FILE_ADD,
        {
            "node_id": "file-1",
            "file_id": "content-1",
            "parent_node_id": "folder-1",
            "name": "report.txt",
            "blob_ids": ["blob-1.enc"],
            "content_hash": "content-hash-1",
            "mime_type": "text/plain",
            "file_size_bytes": 5,
            "encrypted_size_bytes": 11,
            "metadata_json": None,
        },
    )

    folder_result = processor.process_event(folder_event)
    file_result = processor.process_event(file_event)

    assert folder_result.status.value == "success"
    assert file_result.status.value == "success"

    with session_factory() as session:
        refs = session.scalars(
            select(FileReference).order_by(FileReference.virtual_path)
        ).all()
        assert [ref.virtual_path for ref in refs] == ["/docs", "/docs/report.txt"]


def test_process_event_is_idempotent_by_event_id(tmp_path) -> None:
    processor, session_factory = _build_processor(tmp_path)
    event = _event(
        "evt-folder",
        EventType.FOLDER_CREATE,
        {"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
    )

    first = processor.process_event(event)
    second = processor.process_event(event)

    assert first.status.value == "success"
    assert second.status.value == "skipped_idempotent"

    with session_factory() as session:
        processed = session.scalars(select(ProcessedEvent)).all()
        assert len(processed) == 1


def test_process_file_move_updates_parent_and_name(tmp_path) -> None:
    processor, session_factory = _build_processor(tmp_path)
    processor.process_event(
        _event(
            "evt-root",
            EventType.FOLDER_CREATE,
            {"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
        )
    )
    processor.process_event(
        _event(
            "evt-dest",
            EventType.FOLDER_CREATE,
            {"node_id": "folder-2", "parent_node_id": None, "name": "archive"},
        )
    )
    processor.process_event(
        _event(
            "evt-file",
            EventType.FILE_ADD,
            {
                "node_id": "file-1",
                "file_id": "content-1",
                "parent_node_id": "folder-1",
                "name": "report.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
        )
    )

    result = processor.process_event(
        _event(
            "evt-move",
            EventType.FILE_MOVE,
            {
                "node_id": "file-1",
                "new_parent_node_id": "folder-2",
                "new_name": "final.txt",
            },
        )
    )

    assert result.status.value == "success"
    with session_factory() as session:
        ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        assert ref is not None
        assert ref.virtual_path == "/archive/final.txt"


def test_process_file_delete_records_tombstone(tmp_path) -> None:
    processor, session_factory = _build_processor(tmp_path)
    processor.process_event(
        _event(
            "evt-file",
            EventType.FILE_ADD,
            {
                "node_id": "file-1",
                "file_id": "content-1",
                "parent_node_id": None,
                "name": "report.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
        )
    )

    result = processor.process_event(
        _event(
            "evt-delete",
            EventType.FILE_DELETE,
            {"node_id": "file-1", "file_id": "content-1", "reason": "user_action"},
        )
    )

    assert result.status.value == "success"
    with session_factory() as session:
        ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        tombstone = session.scalar(
            select(SyncTombstone).where(SyncTombstone.node_id == "file-1")
        )
        assert ref is None
        assert tombstone is not None
        assert tombstone.node_kind == "file"


def test_process_discovered_event_wraps_process_event(tmp_path) -> None:
    processor, _session_factory = _build_processor(tmp_path)
    discovered = DiscoveredEvent(
        event=_event(
            "evt-db-dump",
            EventType.DB_DUMP_CREATED,
            {
                "device_id": "device-a",
                "created_at": "20260322T000000Z",
                "db_size_bytes": 1024,
                "dump_name": "device-a-20260322T000000Z-db",
            },
        ),
        source_path="vault/events/objects/ab/hash.json",
    )

    result = processor.process_discovered_event(discovered)

    assert result.status.value == "success"


def test_failed_handler_is_not_recorded_as_processed(tmp_path, monkeypatch) -> None:
    processor, session_factory = _build_processor(tmp_path)
    event = _event(
        "evt-folder",
        EventType.FOLDER_CREATE,
        {"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
    )

    def _raise(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(processor, "_handle_folder_create", _raise)

    result = processor.process_event(event)

    assert result.status == ProcessingStatus.FAILED
    with session_factory() as session:
        processed = session.scalars(select(ProcessedEvent)).all()
        assert processed == []


def test_failed_handler_rolls_back_partial_writes(tmp_path, monkeypatch) -> None:
    processor, session_factory = _build_processor(tmp_path)
    event = _event(
        "evt-folder",
        EventType.FOLDER_CREATE,
        {"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
    )

    def _write_then_raise(session, *_args, **_kwargs):
        session.add(
            FileReference(
                node_id="folder-1",
                parent=None,
                name="docs",
                is_folder=True,
                file_entry_id=None,
            )
        )
        session.flush()
        raise RuntimeError("boom")

    monkeypatch.setattr(processor, "_handle_folder_create", _write_then_raise)

    result = processor.process_event(event)

    assert result.status == ProcessingStatus.FAILED
    with session_factory() as session:
        refs = session.scalars(select(FileReference)).all()
        processed = session.scalars(select(ProcessedEvent)).all()
        assert refs == []
        assert processed == []


def test_stale_file_move_is_skipped(tmp_path) -> None:
    processor, session_factory = _build_processor(tmp_path)
    processor.process_event(
        VaultEvent(
            event_id="evt-file",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-1",
                "file_id": "content-1",
                "parent_node_id": None,
                "name": "report.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
            parents=[],
            event_hash="hash-evt-file",
        )
    )
    newer_move = VaultEvent(
        event_id="evt-move-new",
        type=EventType.FILE_MOVE,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-a"),
        payload={
            "node_id": "file-1",
            "new_parent_node_id": None,
            "new_name": "newer.txt",
        },
        parents=[],
        event_hash="hash-evt-move-new",
    )
    older_move = VaultEvent(
        event_id="evt-move-old",
        type=EventType.FILE_MOVE,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=1500, logical=0, device_id="device-a"),
        payload={
            "node_id": "file-1",
            "new_parent_node_id": None,
            "new_name": "older.txt",
        },
        parents=[],
        event_hash="hash-evt-move-old",
    )

    processor.process_event(newer_move)
    result = processor.process_event(older_move)

    assert result.status.value == "skipped_duplicate"
    with session_factory() as session:
        ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        assert ref is not None
        assert ref.name == "newer.txt"


def test_late_file_add_under_deleted_folder_is_archived(tmp_path) -> None:
    processor, session_factory = _build_processor(tmp_path)
    processor.process_event(
        VaultEvent(
            event_id="evt-folder",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
            parents=[],
            event_hash="hash-evt-folder",
        )
    )
    processor.process_event(
        VaultEvent(
            event_id="evt-folder-delete",
            type=EventType.FOLDER_DELETE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-1", "cascade": True},
            parents=[],
            event_hash="hash-evt-folder-delete",
        )
    )

    result = processor.process_event(
        VaultEvent(
            event_id="evt-late-file",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-1",
                "file_id": "content-1",
                "parent_node_id": "folder-1",
                "name": "report.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
            parents=[],
            event_hash="hash-evt-late-file",
        )
    )

    assert result.status.value == "conflict_archived"
    with session_factory() as session:
        conflict_folder = session.scalar(
            select(FileReference).where(FileReference.name == ".glyphweave_conflicts")
        )
        archived = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        assert conflict_folder is not None
        assert archived is not None
        assert archived.parent_id == conflict_folder.id
        assert archived.name.startswith("report.txt.conflict.3000.0.device-a")


def test_file_move_out_of_conflict_folder_resolves_active_conflict(tmp_path) -> None:
    processor, session_factory = _build_processor(tmp_path)
    processor.process_event(
        _event(
            "evt-deleted-parent",
            EventType.FOLDER_CREATE,
            {"node_id": "folder-deleted", "parent_node_id": None, "name": "deleted"},
        )
    )
    processor.process_event(
        _event(
            "evt-live-parent",
            EventType.FOLDER_CREATE,
            {"node_id": "folder-live", "parent_node_id": None, "name": "live"},
        )
    )
    processor.process_event(
        _event(
            "evt-file-add",
            EventType.FILE_ADD,
            {
                "node_id": "file-1",
                "file_id": "content-1",
                "parent_node_id": None,
                "name": "report.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
        )
    )
    processor.process_event(
        _event(
            "evt-delete-parent",
            EventType.FOLDER_DELETE,
            {"node_id": "folder-deleted", "cascade": True},
        )
    )
    archived = processor.process_event(
        _event(
            "evt-file-conflict",
            EventType.FILE_MOVE,
            {
                "node_id": "file-1",
                "new_parent_node_id": "folder-deleted",
                "new_name": "report.txt",
            },
        )
    )

    restored = processor.process_event(
        _event(
            "evt-file-restore",
            EventType.FILE_MOVE,
            {
                "node_id": "file-1",
                "new_parent_node_id": "folder-live",
                "new_name": "restored.txt",
            },
        )
    )

    assert archived.status.value == "conflict_archived"
    assert restored.status.value == "success"
    with session_factory() as session:
        ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        conflict = session.scalar(
            select(SyncConflict).where(SyncConflict.node_id == "file-1")
        )
        assert ref is not None
        assert ref.virtual_path == "/live/restored.txt"
        assert conflict is not None
        assert conflict.status == "resolved"


def test_file_delete_marks_active_conflict_deleted(tmp_path) -> None:
    processor, session_factory = _build_processor(tmp_path)
    processor.process_event(
        _event(
            "evt-deleted-parent",
            EventType.FOLDER_CREATE,
            {"node_id": "folder-deleted", "parent_node_id": None, "name": "deleted"},
        )
    )
    processor.process_event(
        _event(
            "evt-file-add",
            EventType.FILE_ADD,
            {
                "node_id": "file-1",
                "file_id": "content-1",
                "parent_node_id": None,
                "name": "report.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
        )
    )
    processor.process_event(
        _event(
            "evt-delete-parent",
            EventType.FOLDER_DELETE,
            {"node_id": "folder-deleted", "cascade": True},
        )
    )
    processor.process_event(
        _event(
            "evt-file-conflict",
            EventType.FILE_MOVE,
            {
                "node_id": "file-1",
                "new_parent_node_id": "folder-deleted",
                "new_name": "report.txt",
            },
        )
    )

    deleted = processor.process_event(
        _event(
            "evt-file-delete",
            EventType.FILE_DELETE,
            {"node_id": "file-1", "file_id": "content-1", "reason": "user_action"},
        )
    )

    assert deleted.status.value == "success"
    with session_factory() as session:
        ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        conflict = session.scalar(
            select(SyncConflict).where(SyncConflict.node_id == "file-1")
        )
        assert ref is None
        assert conflict is not None
        assert conflict.status == "deleted"


def test_folder_move_out_of_conflict_folder_resolves_descendant_conflicts(
    tmp_path,
) -> None:
    processor, session_factory = _build_processor(tmp_path)
    processor.process_event(
        _event(
            "evt-deleted-parent",
            EventType.FOLDER_CREATE,
            {"node_id": "folder-deleted", "parent_node_id": None, "name": "deleted"},
        )
    )
    processor.process_event(
        _event(
            "evt-live-parent",
            EventType.FOLDER_CREATE,
            {"node_id": "folder-live", "parent_node_id": None, "name": "live"},
        )
    )
    processor.process_event(
        _event(
            "evt-folder-add",
            EventType.FOLDER_CREATE,
            {"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
        )
    )
    processor.process_event(
        _event(
            "evt-file-add",
            EventType.FILE_ADD,
            {
                "node_id": "file-1",
                "file_id": "content-1",
                "parent_node_id": "folder-1",
                "name": "report.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
        )
    )
    processor.process_event(
        _event(
            "evt-delete-parent",
            EventType.FOLDER_DELETE,
            {"node_id": "folder-deleted", "cascade": True},
        )
    )
    processor.process_event(
        _event(
            "evt-folder-conflict",
            EventType.FOLDER_MOVE,
            {
                "node_id": "folder-1",
                "new_parent_node_id": "folder-deleted",
                "new_name": "docs",
            },
        )
    )

    with session_factory.begin() as session:
        child_ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        assert child_ref is not None
        upsert_sync_conflict(
            session,
            conflict_id="conflict-child",
            node_id="file-1",
            node_kind="file",
            archived_name=child_ref.name,
            archived_virtual_path=child_ref.virtual_path,
            archived_file_ref_id=child_ref.id,
            file_entry_id=child_ref.file_entry_id,
            reason_code="deleted_parent_move",
            reason_text="Child conflict",
            trigger_event_id="evt-child",
            trigger_event_hash="hash-child",
            trigger_event_type="file_move",
            origin_device_id="device-a",
        )

    restored = processor.process_event(
        _event(
            "evt-folder-restore",
            EventType.FOLDER_MOVE,
            {
                "node_id": "folder-1",
                "new_parent_node_id": "folder-live",
                "new_name": "docs",
            },
        )
    )

    assert restored.status.value == "success"
    with session_factory() as session:
        folder_ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "folder-1")
        )
        child_ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        conflicts = session.scalars(
            select(SyncConflict).order_by(SyncConflict.conflict_id)
        ).all()
        assert folder_ref is not None
        assert child_ref is not None
        assert folder_ref.virtual_path == "/live/docs"
        assert child_ref.virtual_path == "/live/docs/report.txt"
        assert [conflict.status for conflict in conflicts] == ["resolved", "resolved"]


def test_folder_delete_marks_subtree_conflicts_deleted(tmp_path) -> None:
    processor, session_factory = _build_processor(tmp_path)
    processor.process_event(
        _event(
            "evt-deleted-parent",
            EventType.FOLDER_CREATE,
            {"node_id": "folder-deleted", "parent_node_id": None, "name": "deleted"},
        )
    )
    processor.process_event(
        _event(
            "evt-folder-add",
            EventType.FOLDER_CREATE,
            {"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
        )
    )
    processor.process_event(
        _event(
            "evt-file-add",
            EventType.FILE_ADD,
            {
                "node_id": "file-1",
                "file_id": "content-1",
                "parent_node_id": "folder-1",
                "name": "report.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
        )
    )
    processor.process_event(
        _event(
            "evt-delete-parent",
            EventType.FOLDER_DELETE,
            {"node_id": "folder-deleted", "cascade": True},
        )
    )
    processor.process_event(
        _event(
            "evt-folder-conflict",
            EventType.FOLDER_MOVE,
            {
                "node_id": "folder-1",
                "new_parent_node_id": "folder-deleted",
                "new_name": "docs",
            },
        )
    )

    with session_factory.begin() as session:
        child_ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        assert child_ref is not None
        upsert_sync_conflict(
            session,
            conflict_id="conflict-child",
            node_id="file-1",
            node_kind="file",
            archived_name=child_ref.name,
            archived_virtual_path=child_ref.virtual_path,
            archived_file_ref_id=child_ref.id,
            file_entry_id=child_ref.file_entry_id,
            reason_code="deleted_parent_move",
            reason_text="Child conflict",
            trigger_event_id="evt-child",
            trigger_event_hash="hash-child",
            trigger_event_type="file_move",
            origin_device_id="device-a",
        )

    deleted = processor.process_event(
        _event(
            "evt-folder-delete-conflict",
            EventType.FOLDER_DELETE,
            {"node_id": "folder-1", "cascade": True},
        )
    )

    assert deleted.status.value == "success"
    with session_factory() as session:
        folder_ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "folder-1")
        )
        child_ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        conflicts = session.scalars(
            select(SyncConflict).order_by(SyncConflict.conflict_id)
        ).all()
        assert folder_ref is None
        assert child_ref is None
        assert [conflict.status for conflict in conflicts] == ["deleted", "deleted"]


def test_local_file_add_replay_seeds_sync_state_when_row_already_exists(
    tmp_path,
) -> None:
    processor, session_factory = _build_processor(tmp_path)
    with session_factory() as session:
        file_entry = FileEntry(
            file_id="content-1",
            content_hash="content-hash-1",
            mime_type="text/plain",
            encrypted_size_bytes=11,
            original_size_bytes=5,
            metadata_json=None,
        )
        session.add(file_entry)
        session.flush()
        session.add(
            FileReference(
                node_id="file-1",
                parent=None,
                name="report.txt",
                is_folder=False,
                file_entry_id=file_entry.id,
            )
        )
        session.commit()

    event = VaultEvent(
        event_id="evt-local-file-add",
        type=EventType.FILE_ADD,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=4000, logical=0, device_id="device-a"),
        payload={
            "node_id": "file-1",
            "file_id": "content-1",
            "parent_node_id": None,
            "name": "report.txt",
            "blob_ids": ["blob-1.enc"],
            "content_hash": "content-hash-1",
            "mime_type": "text/plain",
            "file_size_bytes": 5,
            "encrypted_size_bytes": 11,
            "metadata_json": None,
        },
        parents=[],
        event_hash="hash-evt-local-file-add",
    )

    result = processor.process_event(event)

    assert result.status.value == "skipped_idempotent"
    with session_factory() as session:
        state = session.scalar(
            select(SyncNodeState).where(SyncNodeState.node_id == "file-1")
        )
        assert state is not None
        assert state.last_structural_hlc_wall_time == 4000
        assert state.last_content_hlc_wall_time == 4000


def test_local_folder_create_replay_seeds_sync_state_when_row_already_exists(
    tmp_path,
) -> None:
    processor, session_factory = _build_processor(tmp_path)
    with session_factory() as session:
        session.add(
            FileReference(
                node_id="folder-1",
                parent=None,
                name="docs",
                is_folder=True,
                file_entry_id=None,
            )
        )
        session.commit()

    event = VaultEvent(
        event_id="evt-local-folder-add",
        type=EventType.FOLDER_CREATE,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=5000, logical=0, device_id="device-a"),
        payload={"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
        parents=[],
        event_hash="hash-evt-local-folder-add",
    )

    result = processor.process_event(event)

    assert result.status.value == "skipped_idempotent"
    with session_factory() as session:
        state = session.scalar(
            select(SyncNodeState).where(SyncNodeState.node_id == "folder-1")
        )
        assert state is not None
        assert state.last_structural_hlc_wall_time == 5000
        assert state.last_content_hlc_wall_time is None


def test_local_file_delete_replay_records_tombstone_when_row_already_gone(
    tmp_path,
) -> None:
    processor, session_factory = _build_processor(tmp_path)
    event = VaultEvent(
        event_id="evt-local-file-delete",
        type=EventType.FILE_DELETE,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=6000, logical=0, device_id="device-a"),
        payload={"node_id": "file-1", "file_id": "content-1", "reason": "user_action"},
        parents=[],
        event_hash="hash-evt-local-file-delete",
    )

    result = processor.process_event(event)

    assert result.status.value == "skipped_idempotent"
    with session_factory() as session:
        tombstone = session.scalar(
            select(SyncTombstone).where(SyncTombstone.node_id == "file-1")
        )
        state = session.scalar(
            select(SyncNodeState).where(SyncNodeState.node_id == "file-1")
        )
        assert tombstone is not None
        assert tombstone.hlc_wall_time == 6000
        assert state is not None
        assert state.last_structural_hlc_wall_time == 6000
        assert state.last_content_hlc_wall_time == 6000


def test_folder_delete_removes_descendants_recursively(tmp_path) -> None:
    processor, session_factory = _build_processor(tmp_path)
    processor.process_event(
        _event(
            "evt-folder-root",
            EventType.FOLDER_CREATE,
            {"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
        )
    )
    processor.process_event(
        _event(
            "evt-folder-child",
            EventType.FOLDER_CREATE,
            {"node_id": "folder-2", "parent_node_id": "folder-1", "name": "nested"},
        )
    )
    processor.process_event(
        _event(
            "evt-file-child",
            EventType.FILE_ADD,
            {
                "node_id": "file-1",
                "file_id": "content-1",
                "parent_node_id": "folder-2",
                "name": "report.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
        )
    )

    result = processor.process_event(
        _event(
            "evt-folder-delete-recursive",
            EventType.FOLDER_DELETE,
            {"node_id": "folder-1", "cascade": True},
        )
    )

    assert result.status.value == "success"
    with session_factory() as session:
        refs = session.scalars(select(FileReference)).all()
        tombstone = session.scalar(
            select(SyncTombstone).where(SyncTombstone.node_id == "folder-1")
        )
        assert refs == []
        assert tombstone is not None
