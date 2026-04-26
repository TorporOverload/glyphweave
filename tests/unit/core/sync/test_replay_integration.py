import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.common.paths.runtime_layout import replay_checkpoint_path
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import HybridLogicalClock, VaultEvent
from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.event_store import EventStore
from app.infrastructure.persistence.event_store_config import EventStoreConfig
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


def test_replay_handles_missing_parent_reference_gracefully(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    store = _store(vault_path)

    orphan_event = VaultEvent(
        event_id="evt-orphan",
        type=EventType.FILE_ADD,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
        payload={
            "node_id": "file-1",
            "file_id": "content-1",
            "parent_node_id": "nonexistent-parent",
            "name": "orphan.txt",
            "blob_ids": ["blob-1.enc"],
            "content_hash": "content-hash-1",
            "mime_type": "text/plain",
            "file_size_bytes": 5,
            "encrypted_size_bytes": 11,
            "metadata_json": None,
        },
        parents=["nonexistent-parent-event"],
    )

    store.append_event(orphan_event)

    engine = create_engine(f"sqlite:///{tmp_path / 'replay_orphan.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )

    assert result.total == 0
    assert result.successful == 0
    assert result.skipped == 0
    assert result.failed == 0
    assert result.blocked == 1

    with session_factory() as session:
        refs = session.scalars(select(FileReference)).all()
        assert len(refs) == 0


def test_replay_handles_missing_parent_reference_with_valid_folder(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    store = _store(vault_path)

    folder = VaultEvent(
        event_id="evt-folder",
        type=EventType.FOLDER_CREATE,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
        payload={"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
        parents=[],
    )
    store.append_event(folder)

    file_with_missing_parent = VaultEvent(
        event_id="evt-file",
        type=EventType.FILE_ADD,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-a"),
        payload={
            "node_id": "file-1",
            "file_id": "content-1",
            "parent_node_id": "nonexistent-parent",
            "name": "orphan.txt",
            "blob_ids": ["blob-1.enc"],
            "content_hash": "content-hash-1",
            "mime_type": "text/plain",
            "file_size_bytes": 5,
            "encrypted_size_bytes": 11,
            "metadata_json": None,
        },
        parents=["evt-missing-parent"],
    )
    store.append_event(file_with_missing_parent)

    engine = create_engine(f"sqlite:///{tmp_path / 'replay_missing_parent.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )

    assert result.total == 1
    assert result.successful == 1
    assert result.failed == 0
    assert result.blocked == 1

    with session_factory() as session:
        refs = session.scalars(select(FileReference)).all()
        assert len(refs) == 1
        assert refs[0].name == "docs"


def test_replay_out_of_order_events_sorted_by_hlc(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    store = _store(vault_path)

    folder = VaultEvent(
        event_id="evt-folder",
        type=EventType.FOLDER_CREATE,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
        payload={"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
        parents=[],
    )
    store.append_event(folder)

    late_file = VaultEvent(
        event_id="evt-file",
        type=EventType.FILE_ADD,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-a"),
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
    )
    store.append_event(late_file)

    engine = create_engine(f"sqlite:///{tmp_path / 'replay_out_of_order.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )

    assert result.total == 2
    assert result.successful == 2
    assert result.failed == 0
    assert result.blocked == 0

    with session_factory() as session:
        refs = session.scalars(
            select(FileReference).order_by(FileReference.virtual_path)
        ).all()
        assert [ref.virtual_path for ref in refs] == ["/docs", "/docs/report.txt"]


def test_replay_skips_already_processed_events(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    store = _store(vault_path)

    create_folder = VaultEvent(
        event_id="evt-folder",
        type=EventType.FOLDER_CREATE,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
        payload={"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
        parents=[],
    )
    add_file = VaultEvent(
        event_id="evt-file",
        type=EventType.FILE_ADD,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-a"),
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
    )

    store.append_event(create_folder)
    store.append_event(add_file)

    engine = create_engine(f"sqlite:///{tmp_path / 'replay_skipped.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    first = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )
    assert first.total == 2
    assert first.successful == 2

    second = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )
    assert second.total == 0
    assert second.successful == 0
    assert second.skipped == 0

    with session_factory() as session:
        refs = session.scalars(
            select(FileReference).order_by(FileReference.virtual_path)
        ).all()
        assert len(refs) == 2


def test_replay_skips_full_scan_when_checkpoint_matches(tmp_path, monkeypatch) -> None:
    vault_path = tmp_path / "vault"
    local_data_path = tmp_path / "local"
    local_data_path.mkdir(parents=True, exist_ok=True)
    store = _store(vault_path)

    event = VaultEvent(
        event_id="evt-folder",
        type=EventType.FOLDER_CREATE,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
        payload={"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
        parents=[],
    )
    stored = store.append_event(event)

    engine = create_engine(f"sqlite:///{tmp_path / 'replay_checkpoint_integration.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
        local_data_path=local_data_path,
    )

    replay_checkpoint_path(local_data_path).write_text(
        '{"frontier": ["' + stored.event_hash + '"]}',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        store,
        "discover_events",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("unexpected scan")
        ),
    )

    result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
        local_data_path=local_data_path,
    )

    assert result.total == 0
    assert result.failed == 0
