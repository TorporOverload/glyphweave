from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
import threading
import queue
import pytest

from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.infrastructure.persistence.event_store import EventStore
from app.infrastructure.persistence.event_store_config import EventStoreConfig
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import HybridLogicalClock, ProcessingStatus, VaultEvent
from app.services.sync.replay import replay_vault_events


def _store(vault_path):
    return EventStore(
        EventStoreConfig(
            vault_path=vault_path,
            vault_id="vault-1",
            master_key=SecureMemory(b"k" * 32),
            encryption_enabled=True,
        )
    )


def test_multiple_concurrent_conflicts_same_file(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    events = [
        VaultEvent(
            event_id="evt-folder-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-1", "parent_node_id": None, "name": "shared"},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-create",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1100, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-shared",
                "file_id": "content-1",
                "parent_node_id": None,
                "name": "shared.txt",
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
            payload={"node_id": "folder-1", "cascade": True},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-move-a",
            type=EventType.FILE_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-shared",
                "new_parent_node_id": "folder-1",
                "new_name": "shared.txt",
            },
            parents=[],
        ),
        VaultEvent(
            event_id="evt-folder-delete-a",
            type=EventType.FOLDER_DELETE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=4000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-1", "cascade": True},
            parents=[],
        ),
    ]
    for event in events:
        store.append_event(event)

    engine = create_engine(f"sqlite:///{tmp_path / 'concurrent.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )

    assert result.failed == 0
    assert result.conflicts >= 1
    with session_factory() as session:
        conflict_folder = session.scalar(
            select(FileReference).where(FileReference.name == ".glyphweave_conflicts")
        )
        archived = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-shared")
        )
        assert conflict_folder is not None
        assert archived is not None
        assert archived.parent_id == conflict_folder.id
        assert archived.virtual_path.startswith("/.glyphweave_conflicts/")


def test_conflict_resolution_with_missing_blob_reference(tmp_path) -> None:
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
            event_id="evt-file-missing-blob",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-missing-blob",
                "file_id": "content-missing",
                "parent_node_id": "folder-1",
                "name": "orphan.txt",
                "blob_ids": ["nonexistent-blob.enc"],
                "content_hash": "content-hash-missing",
                "mime_type": "text/plain",
                "file_size_bytes": 100,
                "encrypted_size_bytes": 120,
                "metadata_json": None,
            },
            parents=[],
        ),
    ]
    for event in events:
        store.append_event(event)

    engine = create_engine(f"sqlite:///{tmp_path / 'missing_blob.db'}")
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
            select(FileReference).where(FileReference.node_id == "file-missing-blob")
        )
        assert conflict_folder is not None
        assert archived is not None
        assert archived.parent_id == conflict_folder.id
        assert archived.virtual_path.startswith("/.glyphweave_conflicts/")


def test_stale_conflict_archive_event_handling(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    events = [
        VaultEvent(
            event_id="evt-folder-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-1", "parent_node_id": None, "name": "shared"},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-create",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1100, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-stale",
                "file_id": "content-1",
                "parent_node_id": None,
                "name": "stale.txt",
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
            payload={"node_id": "folder-1", "cascade": True},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-move",
            type=EventType.FILE_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-stale",
                "new_parent_node_id": "folder-1",
                "new_name": "stale.txt",
            },
            parents=[],
        ),
    ]
    for event in events:
        store.append_event(event)

    app_data = tmp_path / "device-app"
    app_data.mkdir(parents=True, exist_ok=True)
    (app_data / "device.json").write_text(
        '{"device_id": "device-a", "name": "device-a", "status": "active"}',
        encoding="utf-8",
    )
    local = tmp_path / "device-local"
    local.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{tmp_path / 'stale_archive.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result1 = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
        local_data_path=local,
        app_data_dir=app_data,
    )

    assert result1.conflicts == 1

    conflict_events = [
        discovered.event
        for discovered in store.discover_events()
        if discovered.event.type == EventType.FILE_CONFLICT_ARCHIVE
    ]
    assert len(conflict_events) >= 1

    result2 = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
        local_data_path=local,
        app_data_dir=app_data,
    )

    assert result2.failed == 0
    assert result2.conflicts == 0


def test_archive_event_convergence_across_devices(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    events = [
        VaultEvent(
            event_id="evt-root-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "root", "parent_node_id": None, "name": "root"},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-folder-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1100, logical=0, device_id="device-a"),
            payload={"node_id": "folder-x", "parent_node_id": None, "name": "folder_x"},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-create",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1200, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-converge",
                "file_id": "content-1",
                "parent_node_id": None,
                "name": "converge.txt",
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
            payload={"node_id": "folder-x", "cascade": True},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-move-device-a",
            type=EventType.FILE_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-converge",
                "new_parent_node_id": "folder-x",
                "new_name": "converge.txt",
            },
            parents=[],
        ),
    ]
    for event in events:
        store.append_event(event)

    def replay_for_device(device_id, db_name):
        app_data = tmp_path / f"device-{device_id}-app"
        app_data.mkdir(parents=True, exist_ok=True)
        (app_data / "device.json").write_text(
            '{"device_id": "' + device_id + '", "name": "' + device_id + '", "status": "active"}',
            encoding="utf-8",
        )
        local = tmp_path / f"device-{device_id}-local"
        local.mkdir(parents=True, exist_ok=True)
        engine = create_engine(f"sqlite:///{tmp_path / db_name}")
        Base.metadata.create_all(engine)
        session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        return replay_vault_events(
            session_factory=session_factory,
            vault_path=vault_path,
            store=store,
            local_data_path=local,
            app_data_dir=app_data,
        )

    result_b = replay_for_device("device-b", "device_b_conv.db")
    assert result_b.failed == 0

    result_a = replay_for_device("device-a", "device_a_conv.db")
    assert result_a.failed == 0

    conflict_events = [
        discovered.event
        for discovered in store.discover_events()
        if discovered.event.type == EventType.FILE_CONFLICT_ARCHIVE
    ]
    assert len(conflict_events) >= 1

    result_c = replay_for_device("device-c", "device_c_conv.db")
    assert result_c.failed == 0

    engine_a = create_engine(f"sqlite:///{tmp_path / 'device_a_conv.db'}")
    session_factory_a = sessionmaker(bind=engine_a, autoflush=False, autocommit=False)
    with session_factory_a() as session:
        archived_a = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-converge")
        )
        assert archived_a is not None
        assert archived_a.virtual_path.startswith("/.glyphweave_conflicts/")


def test_conflict_resolution_multiple_files_same_operation(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    events = [
        VaultEvent(
            event_id="evt-folder-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-multi", "parent_node_id": None, "name": "multi"},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-1-create",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1100, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-1",
                "file_id": "content-1",
                "parent_node_id": None,
                "name": "file1.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-2-create",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1200, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-2",
                "file_id": "content-2",
                "parent_node_id": None,
                "name": "file2.txt",
                "blob_ids": ["blob-2.enc"],
                "content_hash": "hash-2",
                "mime_type": "text/plain",
                "file_size_bytes": 6,
                "encrypted_size_bytes": 12,
                "metadata_json": None,
            },
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-3-create",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1300, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-3",
                "file_id": "content-3",
                "parent_node_id": None,
                "name": "file3.txt",
                "blob_ids": ["blob-3.enc"],
                "content_hash": "hash-3",
                "mime_type": "text/plain",
                "file_size_bytes": 7,
                "encrypted_size_bytes": 13,
                "metadata_json": None,
            },
            parents=[],
        ),
        VaultEvent(
            event_id="evt-folder-delete",
            type=EventType.FOLDER_DELETE,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-b"),
            payload={"node_id": "folder-multi", "cascade": True},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-1-move",
            type=EventType.FILE_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-1",
                "new_parent_node_id": "folder-multi",
                "new_name": "file1.txt",
            },
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-2-move",
            type=EventType.FILE_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3100, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-2",
                "new_parent_node_id": "folder-multi",
                "new_name": "file2.txt",
            },
            parents=[],
        ),
        VaultEvent(
            event_id="evt-file-3-move",
            type=EventType.FILE_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3200, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-3",
                "new_parent_node_id": "folder-multi",
                "new_name": "file3.txt",
            },
            parents=[],
        ),
    ]
    for event in events:
        store.append_event(event)

    engine = create_engine(f"sqlite:///{tmp_path / 'multi_conflict.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )

    assert result.failed == 0
    assert result.conflicts >= 3
    with session_factory() as session:
        conflict_folder = session.scalar(
            select(FileReference).where(FileReference.name == ".glyphweave_conflicts")
        )
        assert conflict_folder is not None

        archived_1 = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        archived_2 = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-2")
        )
        archived_3 = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-3")
        )
        assert archived_1 is not None
        assert archived_2 is not None
        assert archived_3 is not None
        assert archived_1.parent_id == conflict_folder.id
        assert archived_2.parent_id == conflict_folder.id
        assert archived_3.parent_id == conflict_folder.id
        assert archived_1.virtual_path.startswith("/.glyphweave_conflicts/")
        assert archived_2.virtual_path.startswith("/.glyphweave_conflicts/")
        assert archived_3.virtual_path.startswith("/.glyphweave_conflicts/")