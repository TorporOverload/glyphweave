import json

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


def test_replay_vault_events_sorts_by_hlc_before_applying(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    early = VaultEvent(
        event_id="evt-early",
        type=EventType.FOLDER_CREATE,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
        payload={"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
        parents=[],
    )
    late = VaultEvent(
        event_id="evt-late",
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

    store.append_event(late)
    store.append_event(early)

    engine = create_engine(f"sqlite:///{tmp_path / 'replay.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )

    assert result.total == 2
    assert result.failed == 0
    with session_factory() as session:
        refs = session.scalars(
            select(FileReference).order_by(FileReference.virtual_path)
        ).all()
        assert [ref.virtual_path for ref in refs] == ["/docs", "/docs/report.txt"]


def test_replay_vault_events_only_applies_new_events(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    create_docs = VaultEvent(
        event_id="evt-folder",
        type=EventType.FOLDER_CREATE,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
        payload={"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
        parents=[],
    )
    add_report = VaultEvent(
        event_id="evt-report",
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
    add_notes = VaultEvent(
        event_id="evt-notes",
        type=EventType.FILE_ADD,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
        payload={
            "node_id": "file-2",
            "file_id": "content-2",
            "parent_node_id": "folder-1",
            "name": "notes.txt",
            "blob_ids": ["blob-2.enc"],
            "content_hash": "content-hash-2",
            "mime_type": "text/plain",
            "file_size_bytes": 7,
            "encrypted_size_bytes": 13,
            "metadata_json": None,
        },
        parents=[],
    )

    store.append_event(create_docs)
    store.append_event(add_report)

    engine = create_engine(f"sqlite:///{tmp_path / 'replay_incremental.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    first = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )
    assert first.total == 2
    assert first.failed == 0

    second = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )
    assert second.total == 0
    assert second.failed == 0

    store.append_event(add_notes)

    third = replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )
    assert third.total == 1
    assert third.failed == 0

    with session_factory() as session:
        refs = session.scalars(
            select(FileReference).order_by(FileReference.virtual_path)
        ).all()
        assert [ref.virtual_path for ref in refs] == [
            "/docs",
            "/docs/notes.txt",
            "/docs/report.txt",
        ]


def test_replay_vault_events_skips_full_scan_when_checkpoint_matches(
    tmp_path,
    monkeypatch,
) -> None:
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

    engine = create_engine(f"sqlite:///{tmp_path / 'replay_checkpoint.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
        local_data_path=local_data_path,
    )
    replay_checkpoint_path(local_data_path).write_text(
        json.dumps({"frontier": [stored.event_hash]}),
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
