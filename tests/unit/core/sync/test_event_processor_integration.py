from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.file_entry import FileEntry
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.model.processed_event import ProcessedEvent
from app.infrastructure.persistence.db.model.sync_tombstone import SyncTombstone
from app.services.sync.event_processor import EventProcessor
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import DiscoveredEvent, HybridLogicalClock, VaultEvent


def _build_processor(tmp_path):
    db_path = tmp_path / "event_processor_integration.db"
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


def test_process_multiple_events_in_sequence_idempotency(tmp_path) -> None:
    processor, session_factory = _build_processor(tmp_path)

    folder_event = _event(
        "evt-folder-seq",
        EventType.FOLDER_CREATE,
        {"node_id": "folder-seq", "parent_node_id": None, "name": "projects"},
    )
    file_event = _event(
        "evt-file-seq",
        EventType.FILE_ADD,
        {
            "node_id": "file-seq",
            "file_id": "content-seq",
            "parent_node_id": "folder-seq",
            "name": "data.txt",
            "blob_ids": ["blob-seq.enc"],
            "content_hash": "content-hash-seq",
            "mime_type": "text/plain",
            "file_size_bytes": 10,
            "encrypted_size_bytes": 22,
            "metadata_json": None,
        },
    )
    move_event = _event(
        "evt-move-seq",
        EventType.FILE_MOVE,
        {
            "node_id": "file-seq",
            "new_parent_node_id": None,
            "new_name": "moved.txt",
        },
    )

    result1 = processor.process_event(folder_event)
    result2 = processor.process_event(file_event)
    result3 = processor.process_event(move_event)

    assert result1.status.value == "success"
    assert result2.status.value == "success"
    assert result3.status.value == "success"

    r1_again = processor.process_event(folder_event)
    r2_again = processor.process_event(file_event)
    r3_again = processor.process_event(move_event)

    assert r1_again.status.value == "skipped_idempotent"
    assert r2_again.status.value == "skipped_idempotent"
    assert r3_again.status.value == "skipped_idempotent"

    with session_factory() as session:
        processed = session.scalars(select(ProcessedEvent)).all()
        assert len(processed) == 3


def test_process_events_with_missing_parent_reference(tmp_path) -> None:
    processor, session_factory = _build_processor(tmp_path)

    file_event = _event(
        "evt-orphan-file",
        EventType.FILE_ADD,
        {
            "node_id": "file-orphan",
            "file_id": "content-orphan",
            "parent_node_id": "nonexistent-folder",
            "name": "orphan.txt",
            "blob_ids": ["blob-orphan.enc"],
            "content_hash": "content-hash-orphan",
            "mime_type": "text/plain",
            "file_size_bytes": 7,
            "encrypted_size_bytes": 15,
            "metadata_json": None,
        },
    )

    result = processor.process_event(file_event)

    assert result.status.value == "failed"


def test_process_stale_events_are_skipped(tmp_path) -> None:
    processor, session_factory = _build_processor(tmp_path)

    processor.process_event(
        VaultEvent(
            event_id="evt-base",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-stale", "parent_node_id": None, "name": "base"},
            parents=[],
            event_hash="hash-evt-base",
        )
    )
    processor.process_event(
        VaultEvent(
            event_id="evt-current",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-stale",
                "file_id": "content-stale",
                "parent_node_id": "folder-stale",
                "name": "current.txt",
                "blob_ids": ["blob-stale.enc"],
                "content_hash": "content-hash-stale",
                "mime_type": "text/plain",
                "file_size_bytes": 8,
                "encrypted_size_bytes": 16,
                "metadata_json": None,
            },
            parents=[],
            event_hash="hash-evt-current",
        )
    )

    stale_file_event = VaultEvent(
        event_id="evt-stale",
        type=EventType.FILE_ADD,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=1500, logical=0, device_id="device-a"),
        payload={
            "node_id": "file-stale",
            "file_id": "content-stale",
            "parent_node_id": "folder-stale",
            "name": "stale.txt",
            "blob_ids": ["blob-stale.enc"],
            "content_hash": "content-hash-stale",
            "mime_type": "text/plain",
            "file_size_bytes": 8,
            "encrypted_size_bytes": 16,
            "metadata_json": None,
        },
        parents=[],
        event_hash="hash-evt-stale",
    )

    result = processor.process_event(stale_file_event)

    assert result.status.value == "skipped_duplicate"

    with session_factory() as session:
        ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-stale")
        )
        assert ref is not None
        assert ref.name == "current.txt"


def test_late_file_add_under_deleted_folder_gets_archived(tmp_path) -> None:
    processor, session_factory = _build_processor(tmp_path)

    processor.process_event(
        VaultEvent(
            event_id="evt-deleted-folder",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-deleted", "parent_node_id": None, "name": "todelete"},
            parents=[],
            event_hash="hash-evt-deleted-folder",
        )
    )
    processor.process_event(
        VaultEvent(
            event_id="evt-folder-gone",
            type=EventType.FOLDER_DELETE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-deleted", "cascade": True},
            parents=[],
            event_hash="hash-evt-folder-gone",
        )
    )

    late_file_event = VaultEvent(
        event_id="evt-late-arriver",
        type=EventType.FILE_ADD,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
        payload={
            "node_id": "file-late",
            "file_id": "content-late",
            "parent_node_id": "folder-deleted",
            "name": "latecomer.txt",
            "blob_ids": ["blob-late.enc"],
            "content_hash": "content-hash-late",
            "mime_type": "text/plain",
            "file_size_bytes": 6,
            "encrypted_size_bytes": 12,
            "metadata_json": None,
        },
        parents=[],
        event_hash="hash-evt-late-arriver",
    )

    result = processor.process_event(late_file_event)

    assert result.status.value == "conflict_archived"

    with session_factory() as session:
        conflict_folder = session.scalar(
            select(FileReference).where(FileReference.name == ".glyphweave_conflicts")
        )
        archived = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-late")
        )
        assert conflict_folder is not None
        assert archived is not None
        assert archived.parent_id == conflict_folder.id
        assert archived.name.startswith("latecomer.txt.conflict.")
