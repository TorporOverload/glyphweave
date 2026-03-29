from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
import json
import pytest

from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.infrastructure.persistence.event_store import EventStore
from app.infrastructure.persistence.event_store_config import EventStoreConfig
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import HybridLogicalClock, VaultEvent
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
        assert conflict_folder is not None
        assert archived is not None
        assert archived.parent_id == conflict_folder.id
        assert archived.virtual_path.startswith("/.glyphweave_conflicts/")


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

    with pytest.raises(ValueError, match="Invalid parent node: missing-parent"):
        replay_vault_events(
            session_factory=session_factory,
            vault_path=vault_path,
            store=store,
        )


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
        assert archived_b is not None
        assert archived_b.virtual_path.startswith("/.glyphweave_conflicts/")

    conflict_events = [
        discovered.event
        for discovered in store.discover_events()
        if discovered.event.type == EventType.FILE_CONFLICT_ARCHIVE
    ]
    assert len(conflict_events) >= 1

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
        assert archived_a is not None
        assert archived_a.virtual_path.startswith("/.glyphweave_conflicts/")
