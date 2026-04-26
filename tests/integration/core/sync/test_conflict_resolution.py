import json
import pytest
from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.common.paths.runtime_layout import replay_checkpoint_path
from app.infrastructure.persistence.db.base_model import Base
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.model.sync_conflict import SyncConflict
from app.infrastructure.persistence.db.service.session import session_scope
from app.infrastructure.persistence.db.service.sync_conflict_service import (
    list_active_sync_conflicts,
)
from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.infrastructure.persistence.event_store import EventStore
from app.infrastructure.persistence.event_store_config import EventStoreConfig
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import HybridLogicalClock, VaultEvent
from app.services.sync.event_processor import ProcessingStatus
from app.services.sync.event_emitter import EventEmitter
from app.services.sync.replay import replay_vault_events


def _store(vault_path) -> EventStore:
    return EventStore(
        EventStoreConfig(
            vault_path=vault_path,
            vault_id="vault-1",
            master_key=SecureMemory(b"k" * 32),
            encryption_enabled=True,
        )
    )


def test_replay_archives_late_file_add_after_folder_delete(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    events = [
        VaultEvent(
            event_id="evt-folder-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-folder-delete",
            type=EventType.FOLDER_DELETE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-1", "cascade": True},
            parents=[],
        ),
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
        ),
    ]
    for event in events:
        store.append_event(event)

    engine = create_engine(f"sqlite:///{tmp_path / 'conflict.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )

    assert result.conflicts == 1
    with session_factory() as session:
        conflict_folder = session.scalar(
            select(FileReference).where(FileReference.name == ".glyphweave_conflicts")
        )
        archived = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        sync_conflicts = session.scalars(select(SyncConflict)).all()
        assert conflict_folder is not None
        assert archived is not None
        assert archived.parent_id == conflict_folder.id
        assert archived.virtual_path.startswith("/.glyphweave_conflicts/")
        assert len(sync_conflicts) == 1
        assert sync_conflicts[0].node_id == "file-1"
        assert sync_conflicts[0].reason_code == "deleted_parent_add"
        assert sync_conflicts[0].status == "active"


def test_replay_file_add_with_missing_parent_does_not_crash(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    store.append_event(
        VaultEvent(
            event_id="evt-missing-parent-file-add",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-1",
                "file_id": "content-1",
                "parent_node_id": "missing-parent",
                "name": "report.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
            parents=[],
        )
    )

    engine = create_engine(f"sqlite:///{tmp_path / 'missing_parent.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )

    assert result.failed == 1
    assert result.results[0].status == ProcessingStatus.FAILED


def test_replay_blocks_resolution_until_conflict_archive_blobs_exist(tmp_path) -> None:
    vault_path = tmp_path / "vault-blocked-conflict"
    (vault_path / "blobs").mkdir(parents=True, exist_ok=True)
    store = _store(vault_path)
    store.append_event(
        VaultEvent(
            event_id="evt-live-folder-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-live", "parent_node_id": None, "name": "live"},
            parents=[],
        )
    )
    archive = store.append_event(
        VaultEvent(
            event_id="evt-file-conflict-archive",
            type=EventType.FILE_CONFLICT_ARCHIVE,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-b"),
            payload={
                "conflict_id": "conflict-1",
                "node_id": "file-1",
                "file_id": "content-1",
                "parent_node_id": "conflicts-root",
                "name": "report.txt.conflict",
                "archived_name": "report.txt.conflict",
                "blob_ids": ["missing.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
                "reason_code": "deleted_parent_move",
                "reason_text": "File move targeted a deleted parent",
                "trigger_event_id": "evt-trigger",
                "trigger_event_type": "file_move",
                "trigger_device_id": "device-b",
                "origin_device_id": "device-b",
            },
            parents=[],
        )
    )
    restored = store.append_event(
        VaultEvent(
            event_id="evt-file-restore",
            type=EventType.FILE_MOVE,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-b"),
            payload={
                "node_id": "file-1",
                "new_parent_node_id": "folder-live",
                "new_name": "restored.txt",
            },
            parents=[archive.event_hash],
        )
    )
    store.append_event(
        VaultEvent(
            event_id="evt-file-conflict-resolved",
            type=EventType.FILE_CONFLICT_RESOLVED,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=3100, logical=0, device_id="device-b"),
            payload={
                "conflict_id": "conflict-1",
                "node_id": "file-1",
                "resolution_status": "resolved",
                "resolution_reason": "explicit_restore",
                "origin_device_id": "device-b",
            },
            parents=[restored.event_hash],
        )
    )

    app_data_dir = tmp_path / "app-data"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    local_data_path = tmp_path / "local-data"
    local_data_path.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{tmp_path / 'blocked_conflict.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    first_result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
        local_data_path=local_data_path,
        app_data_dir=app_data_dir,
    )

    assert first_result.total == 1
    assert replay_checkpoint_path(local_data_path).exists() is False
    with session_factory() as session:
        assert session.scalar(select(SyncConflict)) is None
        live_folder = session.scalar(
            select(FileReference).where(FileReference.node_id == "folder-live")
        )
        archived = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        assert live_folder is not None
        assert archived is None

    (vault_path / "blobs" / "missing.enc").write_bytes(b"x")

    second_result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
        local_data_path=local_data_path,
        app_data_dir=app_data_dir,
    )

    assert second_result.total == 3
    checkpoint = json.loads(replay_checkpoint_path(local_data_path).read_text("utf-8"))
    assert checkpoint["frontier"] == sorted(store.iter_frontier_hashes())
    with session_factory() as session:
        conflict = session.scalar(select(SyncConflict))
        restored_ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        assert conflict is not None
        assert conflict.status == "resolved"
        assert restored_ref is not None
        assert restored_ref.virtual_path == "/live/restored.txt"


def test_replay_archives_file_move_into_deleted_parent(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    events = [
        VaultEvent(
            event_id="evt-folder-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-d", "parent_node_id": None, "name": "folder_d"},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-create",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1100, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-a",
                "file_id": "content-1",
                "parent_node_id": None,
                "name": "file_a.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
            parents=[],
        ),
        VaultEvent(
            event_id="evt-folder-delete",
            type=EventType.FOLDER_DELETE,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-b"),
            payload={"node_id": "folder-d", "cascade": True},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-move",
            type=EventType.FILE_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-a",
                "new_parent_node_id": "folder-d",
                "new_name": "file_a.txt",
            },
            parents=[],
        ),
    ]
    for event in events:
        store.append_event(event)

    engine = create_engine(f"sqlite:///{tmp_path / 'move_conflict.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )

    assert result.failed == 0
    assert result.conflicts == 1
    with session_factory() as session:
        conflict_folder = session.scalar(
            select(FileReference).where(FileReference.name == ".glyphweave_conflicts")
        )
        archived = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-a")
        )
        assert conflict_folder is not None
        assert archived is not None
        assert archived.parent_id == conflict_folder.id
        assert archived.virtual_path.startswith("/.glyphweave_conflicts/")


def test_conflict_archive_event_converges_archived_file_across_devices(
    tmp_path,
) -> None:
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    events = [
        VaultEvent(
            event_id="evt-folder-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-d", "parent_node_id": None, "name": "folder_d"},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-create",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1100, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-a",
                "file_id": "content-1",
                "parent_node_id": None,
                "name": "file_a.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
            parents=[],
        ),
        VaultEvent(
            event_id="evt-folder-delete-device-b",
            type=EventType.FOLDER_DELETE,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-b"),
            payload={"node_id": "folder-d", "cascade": True},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-move-device-a",
            type=EventType.FILE_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-a",
                "new_parent_node_id": "folder-d",
                "new_name": "file_a.txt",
            },
            parents=[],
        ),
        VaultEvent(
            event_id="evt-folder-delete-device-a",
            type=EventType.FOLDER_DELETE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=4000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-d", "cascade": True},
            parents=[],
        ),
    ]
    for event in events:
        store.append_event(event)

    app_data_b = tmp_path / "device-b-app"
    app_data_b.mkdir(parents=True, exist_ok=True)
    (app_data_b / "device.json").write_text(
        json.dumps({"device_id": "device-b", "name": "B", "status": "active"}),
        encoding="utf-8",
    )
    local_b = tmp_path / "device-b-local"
    local_b.mkdir(parents=True, exist_ok=True)
    engine_b = create_engine(f"sqlite:///{tmp_path / 'device_b.db'}")
    Base.metadata.create_all(engine_b)
    session_factory_b = sessionmaker(bind=engine_b, autoflush=False, autocommit=False)

    result_b = replay_vault_events(
        session_factory=session_factory_b,
        vault_path=vault_path,
        store=store,
        local_data_path=local_b,
        app_data_dir=app_data_b,
    )

    assert result_b.failed == 0
    with session_factory_b() as session:
        archived_b = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-a")
        )
        conflict_b = session.scalar(
            select(SyncConflict).where(SyncConflict.node_id == "file-a")
        )
        assert archived_b is not None
        assert archived_b.virtual_path.startswith("/.glyphweave_conflicts/")
        assert conflict_b is not None
        assert conflict_b.reason_code == "deleted_parent_move"
        assert conflict_b.status == "active"

    with session_scope(session_factory_b, commit=False) as session:
        active_conflicts_b = list_active_sync_conflicts(session)
        assert len(active_conflicts_b) == 1
        assert active_conflicts_b[0].conflict_id == conflict_b.conflict_id

    conflict_events = [
        discovered.event
        for discovered in store.discover_events()
        if discovered.event.type == EventType.FILE_CONFLICT_ARCHIVE
    ]
    assert len(conflict_events) == 1

    app_data_a = tmp_path / "device-a-app"
    app_data_a.mkdir(parents=True, exist_ok=True)
    (app_data_a / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    local_a = tmp_path / "device-a-local"
    local_a.mkdir(parents=True, exist_ok=True)
    engine_a = create_engine(f"sqlite:///{tmp_path / 'device_a.db'}")
    Base.metadata.create_all(engine_a)
    session_factory_a = sessionmaker(bind=engine_a, autoflush=False, autocommit=False)

    result_a = replay_vault_events(
        session_factory=session_factory_a,
        vault_path=vault_path,
        store=store,
        local_data_path=local_a,
        app_data_dir=app_data_a,
    )

    assert result_a.failed == 0
    with session_factory_a() as session:
        archived_a = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-a")
        )
        conflict_a = session.scalar(
            select(SyncConflict).where(SyncConflict.node_id == "file-a")
        )
        assert archived_a is not None
        assert archived_a.virtual_path.startswith("/.glyphweave_conflicts/")
        assert conflict_a is not None
        assert conflict_a.conflict_id == conflict_events[0].payload["conflict_id"]
        assert conflict_a.reason_code == "deleted_parent_move"
        assert conflict_a.status == "active"

    emitter_b = EventEmitter(
        store=store,
        app_data_dir=app_data_b,
        session_factory=session_factory_b,
        local_data_path=local_b,
    )
    emitter_b.emit_file_delete(SimpleNamespace(node_id="file-a"), file_id="content-1")
    emitter_b.emit_file_conflict_resolved(
        conflict_id=conflict_b.conflict_id,
        node_id="file-a",
        resolution_status="deleted",
        resolution_reason="explicit_delete",
    )

    with session_factory_b() as session:
        deleted_conflict_b = session.scalar(
            select(SyncConflict).where(
                SyncConflict.conflict_id == conflict_b.conflict_id
            )
        )
        archived_b_after = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-a")
        )
        assert deleted_conflict_b is not None
        assert deleted_conflict_b.status == "deleted"
        assert archived_b_after is None

    result_a_after_delete = replay_vault_events(
        session_factory=session_factory_a,
        vault_path=vault_path,
        store=store,
        local_data_path=local_a,
        app_data_dir=app_data_a,
    )

    assert result_a_after_delete.failed == 0
    with session_factory_a() as session:
        deleted_conflict_a = session.scalar(
            select(SyncConflict).where(
                SyncConflict.conflict_id == conflict_b.conflict_id
            )
        )
        archived_a_after = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-a")
        )
        assert deleted_conflict_a is not None
        assert deleted_conflict_a.status == "deleted"
        assert archived_a_after is None


def test_conflict_archive_event_converges_archived_folder_across_devices(
    tmp_path,
) -> None:
    vault_path = tmp_path / "vault-folder"
    store = _store(vault_path)
    events = [
        VaultEvent(
            event_id="evt-parent-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "parent", "parent_node_id": None, "name": "parent"},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-folder-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1100, logical=0, device_id="device-a"),
            payload={"node_id": "folder-a", "parent_node_id": None, "name": "folder_a"},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-parent-delete-b",
            type=EventType.FOLDER_DELETE,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-b"),
            payload={"node_id": "parent", "cascade": True},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-folder-move-a",
            type=EventType.FOLDER_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "folder-a",
                "new_parent_node_id": "parent",
                "new_name": "folder_a",
            },
            parents=[],
        ),
    ]
    for event in events:
        store.append_event(event)

    app_data_b = tmp_path / "folder-device-b-app"
    app_data_b.mkdir(parents=True, exist_ok=True)
    (app_data_b / "device.json").write_text(
        json.dumps({"device_id": "device-b", "name": "B", "status": "active"}),
        encoding="utf-8",
    )
    local_b = tmp_path / "folder-device-b-local"
    local_b.mkdir(parents=True, exist_ok=True)
    engine_b = create_engine(f"sqlite:///{tmp_path / 'folder_device_b.db'}")
    Base.metadata.create_all(engine_b)
    session_factory_b = sessionmaker(bind=engine_b, autoflush=False, autocommit=False)

    result_b = replay_vault_events(
        session_factory=session_factory_b,
        vault_path=vault_path,
        store=store,
        local_data_path=local_b,
        app_data_dir=app_data_b,
    )

    assert result_b.failed == 0
    with session_factory_b() as session:
        archived_b = session.scalar(
            select(FileReference).where(FileReference.node_id == "folder-a")
        )
        conflict_b = session.scalar(
            select(SyncConflict).where(SyncConflict.node_id == "folder-a")
        )
        assert archived_b is not None
        assert archived_b.virtual_path.startswith("/.glyphweave_conflicts/")
        assert archived_b.is_folder is True
        assert conflict_b is not None
        assert conflict_b.reason_code == "deleted_parent_folder_move"

    conflict_events = [
        discovered.event
        for discovered in store.discover_events()
        if discovered.event.type == EventType.FOLDER_CONFLICT_ARCHIVE
    ]
    assert len(conflict_events) == 1

    app_data_a = tmp_path / "folder-device-a-app"
    app_data_a.mkdir(parents=True, exist_ok=True)
    (app_data_a / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    local_a = tmp_path / "folder-device-a-local"
    local_a.mkdir(parents=True, exist_ok=True)
    engine_a = create_engine(f"sqlite:///{tmp_path / 'folder_device_a.db'}")
    Base.metadata.create_all(engine_a)
    session_factory_a = sessionmaker(bind=engine_a, autoflush=False, autocommit=False)

    result_a = replay_vault_events(
        session_factory=session_factory_a,
        vault_path=vault_path,
        store=store,
        local_data_path=local_a,
        app_data_dir=app_data_a,
    )

    assert result_a.failed == 0
    with session_factory_a() as session:
        archived_a = session.scalar(
            select(FileReference).where(FileReference.node_id == "folder-a")
        )
        conflict_a = session.scalar(
            select(SyncConflict).where(SyncConflict.node_id == "folder-a")
        )
        assert archived_a is not None
        assert archived_a.virtual_path.startswith("/.glyphweave_conflicts/")
        assert archived_a.is_folder is True
        assert conflict_a is not None
        assert conflict_a.conflict_id == conflict_events[0].payload["conflict_id"]
        assert conflict_a.reason_code == "deleted_parent_folder_move"

    emitter_b = EventEmitter(
        store=store,
        app_data_dir=app_data_b,
        session_factory=session_factory_b,
        local_data_path=local_b,
    )
    emitter_b.emit_folder_delete(
        SimpleNamespace(node_id="folder-a"),
        cascade=True,
    )
    emitter_b.emit_folder_conflict_resolved(
        conflict_id=conflict_b.conflict_id,
        node_id="folder-a",
        resolution_status="deleted",
        resolution_reason="explicit_delete",
    )

    result_a_after_delete = replay_vault_events(
        session_factory=session_factory_a,
        vault_path=vault_path,
        store=store,
        local_data_path=local_a,
        app_data_dir=app_data_a,
    )

    assert result_a_after_delete.failed == 0
    with session_factory_a() as session:
        deleted_conflict_a = session.scalar(
            select(SyncConflict).where(
                SyncConflict.conflict_id == conflict_b.conflict_id
            )
        )
        archived_a_after = session.scalar(
            select(FileReference).where(FileReference.node_id == "folder-a")
        )
        assert deleted_conflict_a is not None
        assert deleted_conflict_a.status == "deleted"
        assert archived_a_after is None


def test_replay_skips_stale_file_conflict_archive_event(tmp_path) -> None:
    vault_path = tmp_path / "vault-stale-file"
    store = _store(vault_path)
    initial_events = [
        VaultEvent(
            event_id="evt-file-create",
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
        ),
        VaultEvent(
            event_id="evt-file-restore",
            type=EventType.FILE_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-1",
                "new_parent_node_id": None,
                "new_name": "restored.txt",
            },
            parents=[],
        ),
    ]
    for event in initial_events:
        store.append_event(event)

    engine = create_engine(f"sqlite:///{tmp_path / 'stale_file_conflict.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    first_result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )
    assert first_result.failed == 0

    store.append_event(
        VaultEvent(
            event_id="evt-stale-file-conflict-archive",
            type=EventType.FILE_CONFLICT_ARCHIVE,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-b"),
            payload={
                "conflict_id": "conflict-file-1",
                "node_id": "file-1",
                "file_id": "content-1",
                "name": "report.txt.conflict",
                "archived_name": "report.txt.conflict",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
                "reason_code": "deleted_parent_move",
                "reason_text": "File move targeted a parent folder that had been deleted",
                "trigger_event_id": "evt-trigger",
                "trigger_event_type": "file_move",
                "trigger_device_id": "device-b",
                "origin_device_id": "device-b",
            },
            parents=[],
        )
    )

    second_result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )

    assert second_result.failed == 0
    with session_factory() as session:
        file_ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        conflict = session.scalar(
            select(SyncConflict).where(SyncConflict.node_id == "file-1")
        )
        assert file_ref is not None
        assert file_ref.virtual_path == "/restored.txt"
        assert conflict is None


def test_replay_skips_stale_file_conflict_archive_when_content_is_newer(
    tmp_path,
) -> None:
    vault_path = tmp_path / "vault-stale-file-content"
    store = _store(vault_path)
    initial_events = [
        VaultEvent(
            event_id="evt-file-create",
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
        ),
        VaultEvent(
            event_id="evt-file-update",
            type=EventType.FILE_UPDATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-1",
                "old_file_id": "content-1",
                "new_file_id": "content-2",
                "old_blob_ids": ["blob-1.enc"],
                "new_blob_ids": ["blob-2.enc"],
                "old_content_hash": "content-hash-1",
                "new_content_hash": "content-hash-2",
                "new_file_size_bytes": 7,
                "new_encrypted_size_bytes": 13,
                "new_metadata_json": None,
            },
            parents=[],
        ),
    ]
    for event in initial_events:
        store.append_event(event)

    engine = create_engine(f"sqlite:///{tmp_path / 'stale_file_content_conflict.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    first_result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )
    assert first_result.failed == 0

    store.append_event(
        VaultEvent(
            event_id="evt-stale-file-conflict-archive-content",
            type=EventType.FILE_CONFLICT_ARCHIVE,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-b"),
            payload={
                "conflict_id": "conflict-file-1",
                "node_id": "file-1",
                "file_id": "content-1",
                "name": "report.txt.conflict",
                "archived_name": "report.txt.conflict",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
                "reason_code": "deleted_parent_move",
                "reason_text": "File move targeted a parent folder that had been deleted",
                "trigger_event_id": "evt-trigger",
                "trigger_event_type": "file_move",
                "trigger_device_id": "device-b",
                "origin_device_id": "device-b",
            },
            parents=[],
        )
    )

    second_result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )

    assert second_result.failed == 0
    with session_factory() as session:
        file_ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        conflict = session.scalar(
            select(SyncConflict).where(SyncConflict.node_id == "file-1")
        )
        assert file_ref is not None
        assert file_ref.virtual_path == "/report.txt"
        assert file_ref.file_entry is not None
        assert file_ref.file_entry.content_hash == "content-hash-2"
        assert conflict is None


def test_replay_skips_stale_folder_conflict_archive_event(tmp_path) -> None:
    vault_path = tmp_path / "vault-stale-folder"
    store = _store(vault_path)
    initial_events = [
        VaultEvent(
            event_id="evt-folder-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={
                "node_id": "folder-1",
                "parent_node_id": None,
                "name": "folder_a",
            },
            parents=[],
        ),
        VaultEvent(
            event_id="evt-folder-restore",
            type=EventType.FOLDER_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "folder-1",
                "new_parent_node_id": None,
                "new_name": "restored_folder",
            },
            parents=[],
        ),
    ]
    for event in initial_events:
        store.append_event(event)

    engine = create_engine(f"sqlite:///{tmp_path / 'stale_folder_conflict.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    first_result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )
    assert first_result.failed == 0

    store.append_event(
        VaultEvent(
            event_id="evt-stale-folder-conflict-archive",
            type=EventType.FOLDER_CONFLICT_ARCHIVE,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-b"),
            payload={
                "conflict_id": "conflict-folder-1",
                "node_id": "folder-1",
                "archived_name": "folder_a.conflict",
                "reason_code": "deleted_parent_folder_move",
                "reason_text": "Folder move targeted a parent folder that had been deleted",
                "trigger_event_id": "evt-trigger-folder",
                "trigger_event_type": "folder_move",
                "trigger_device_id": "device-b",
                "origin_device_id": "device-b",
            },
            parents=[],
        )
    )

    second_result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )

    assert second_result.failed == 0
    with session_factory() as session:
        folder_ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "folder-1")
        )
        conflict = session.scalar(
            select(SyncConflict).where(SyncConflict.node_id == "folder-1")
        )
        assert folder_ref is not None
        assert folder_ref.virtual_path == "/restored_folder"
        assert conflict is None


def test_replay_skips_folder_conflict_archive_emission_after_same_batch_delete(
    tmp_path,
) -> None:
    vault_path = tmp_path / "vault-folder-delete"
    store = _store(vault_path)
    events = [
        VaultEvent(
            event_id="evt-parent-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "parent", "parent_node_id": None, "name": "parent"},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-folder-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1100, logical=0, device_id="device-a"),
            payload={
                "node_id": "folder-a",
                "parent_node_id": None,
                "name": "folder_a",
            },
            parents=[],
        ),
        VaultEvent(
            event_id="evt-parent-delete",
            type=EventType.FOLDER_DELETE,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-b"),
            payload={"node_id": "parent", "cascade": True},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-folder-move",
            type=EventType.FOLDER_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "folder-a",
                "new_parent_node_id": "parent",
                "new_name": "folder_a",
            },
            parents=[],
        ),
        VaultEvent(
            event_id="evt-folder-delete",
            type=EventType.FOLDER_DELETE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=4000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-a", "cascade": True},
            parents=[],
        ),
    ]
    for event in events:
        store.append_event(event)

    app_data_dir = tmp_path / "app-data"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    local_data_path = tmp_path / "local-data"
    local_data_path.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{tmp_path / 'folder_delete_batch.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
        local_data_path=local_data_path,
        app_data_dir=app_data_dir,
    )

    assert result.failed == 0
    with session_factory() as session:
        folder_ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "folder-a")
        )
        conflicts = session.scalars(select(SyncConflict)).all()
        assert folder_ref is None
        assert [conflict.status for conflict in conflicts] == ["deleted"]

    conflict_archive_events = [
        discovered.event
        for discovered in store.discover_events()
        if discovered.event.type == EventType.FOLDER_CONFLICT_ARCHIVE
    ]
    assert conflict_archive_events == []


def test_replay_skips_file_conflict_archive_emission_after_same_batch_restore(
    tmp_path,
) -> None:
    vault_path = tmp_path / "vault-file-restore"
    store = _store(vault_path)
    events = [
        VaultEvent(
            event_id="evt-parent-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "parent", "parent_node_id": None, "name": "parent"},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-live-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1100, logical=0, device_id="device-a"),
            payload={"node_id": "live", "parent_node_id": None, "name": "live"},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-create",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1200, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-a",
                "file_id": "content-1",
                "parent_node_id": None,
                "name": "file_a.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
            parents=[],
        ),
        VaultEvent(
            event_id="evt-parent-delete",
            type=EventType.FOLDER_DELETE,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-b"),
            payload={"node_id": "parent", "cascade": True},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-conflict",
            type=EventType.FILE_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-a",
                "new_parent_node_id": "parent",
                "new_name": "file_a.txt",
            },
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-restore",
            type=EventType.FILE_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=4000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-a",
                "new_parent_node_id": "live",
                "new_name": "restored.txt",
            },
            parents=[],
        ),
    ]
    for event in events:
        store.append_event(event)

    app_data_dir = tmp_path / "app-data-file"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    local_data_path = tmp_path / "local-data-file"
    local_data_path.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{tmp_path / 'file_restore_batch.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
        local_data_path=local_data_path,
        app_data_dir=app_data_dir,
    )

    assert result.failed == 0
    with session_factory() as session:
        file_ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-a")
        )
        conflicts = session.scalars(select(SyncConflict)).all()
        assert file_ref is not None
        assert file_ref.virtual_path == "/live/restored.txt"
        assert [conflict.status for conflict in conflicts] == ["resolved"]

    conflict_archive_events = [
        discovered.event
        for discovered in store.discover_events()
        if discovered.event.type == EventType.FILE_CONFLICT_ARCHIVE
    ]
    assert conflict_archive_events == []
