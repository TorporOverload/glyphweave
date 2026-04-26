import json

import app.core.domain.sync.hlc as hlc_module
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import HybridLogicalClock, VaultEvent
from app.common.paths.runtime_layout import replay_checkpoint_path
from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.processed_event import ProcessedEvent
from app.infrastructure.persistence.event_store import EventStore
from app.infrastructure.persistence.event_store_config import EventStoreConfig
from app.services.sync.event_emitter import EventEmitter


class _Blob:
    def __init__(self, blob_id: str) -> None:
        self.blob_id = blob_id


class _Entry:
    def __init__(
        self,
        *,
        name: str,
        node_id: str,
        parent=None,
        file_entry=None,
        is_folder: bool = False,
    ) -> None:
        self.name = name
        self.node_id = node_id
        self.parent = parent
        self.file_entry = file_entry
        self.is_folder = is_folder


class _FileEntry:
    def __init__(self) -> None:
        self.file_id = "file-1"
        self.blobs = [_Blob("blob-1.enc")]
        self.content_hash = "hash-1"
        self.mime_type = "text/plain"
        self.original_size_bytes = 5
        self.encrypted_size_bytes = 11
        self.metadata_json = None


def _store(vault_path) -> EventStore:
    return EventStore(
        EventStoreConfig(
            vault_path=vault_path,
            vault_id="vault-1",
            master_key=SecureMemory(b"k" * 32),
            encryption_enabled=True,
        )
    )


def test_event_emitter_writes_events_and_chains_frontier(tmp_path) -> None:
    app_data_dir = tmp_path / "app"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    emitter = EventEmitter(store=store, app_data_dir=app_data_dir)

    root = _Entry(name="docs", node_id="folder-1", is_folder=True)
    child = _Entry(
        name="report.txt",
        node_id="node-1",
        parent=root,
        file_entry=_FileEntry(),
    )

    folder_event = emitter.emit_folder_create(root)
    file_event = emitter.emit_file_add(child)

    assert folder_event.event_hash is not None
    assert file_event.event_hash is not None
    assert file_event.parents == [folder_event.event_hash]
    payload = json.loads(
        store.object_path(file_event.event_hash).read_text(encoding="utf-8")
    )
    assert payload["mode"] == "encrypted"


def test_event_emitter_observes_existing_remote_hlc_on_startup(
    monkeypatch, tmp_path
) -> None:
    app_data_dir = tmp_path / "app"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    remote_event = VaultEvent(
        event_id="evt-remote",
        type=EventType.FOLDER_CREATE,
        device_id="device-b",
        hlc=HybridLogicalClock(wall_time=2000, logical=4, device_id="device-b"),
        payload={"node_id": "remote-folder", "parent_node_id": None, "name": "shared"},
        parents=[],
    )
    store.append_event(remote_event)
    monkeypatch.setattr(hlc_module.time, "time", lambda: 0.002)

    emitter = EventEmitter(store=store, app_data_dir=app_data_dir)
    local_event = emitter.emit_folder_create(
        _Entry(name="docs", node_id="folder-1", is_folder=True)
    )

    assert local_event.hlc == HybridLogicalClock(
        wall_time=2000,
        logical=1,
        device_id="device-a",
    )


def test_event_emitter_seeds_hlc_from_frontier_heads_without_full_scan(
    monkeypatch,
    tmp_path,
) -> None:
    app_data_dir = tmp_path / "app"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    remote_event = VaultEvent(
        event_id="evt-remote",
        type=EventType.FOLDER_CREATE,
        device_id="device-b",
        hlc=HybridLogicalClock(wall_time=2000, logical=4, device_id="device-b"),
        payload={"node_id": "remote-folder", "parent_node_id": None, "name": "shared"},
        parents=[],
    )
    store.append_event(remote_event)
    monkeypatch.setattr(
        store,
        "discover_events",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("unexpected full scan")
        ),
    )
    monkeypatch.setattr(hlc_module.time, "time", lambda: 0.002)

    emitter = EventEmitter(store=store, app_data_dir=app_data_dir)
    local_event = emitter.emit_folder_create(
        _Entry(name="docs", node_id="folder-1", is_folder=True)
    )

    assert local_event.hlc == HybridLogicalClock(
        wall_time=2000,
        logical=1,
        device_id="device-a",
    )


def test_event_emitter_processes_local_event_and_refreshes_checkpoint(tmp_path) -> None:
    app_data_dir = tmp_path / "app"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    local_data_path = tmp_path / "local"
    local_data_path.mkdir(parents=True, exist_ok=True)
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    engine = create_engine(f"sqlite:///{tmp_path / 'event_emitter.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    emitter = EventEmitter(
        store=store,
        app_data_dir=app_data_dir,
        session_factory=session_factory,
        local_data_path=local_data_path,
    )
    event = emitter.emit_folder_create(
        _Entry(name="docs", node_id="folder-1", is_folder=True)
    )

    with session_factory() as session:
        processed = session.scalars(select(ProcessedEvent)).all()

    assert len(processed) == 1
    assert processed[0].event_hash == event.event_hash
    checkpoint = json.loads(
        replay_checkpoint_path(local_data_path).read_text(encoding="utf-8")
    )
    assert checkpoint["frontier"] == [event.event_hash]


def test_event_emitter_preserves_existing_frontier_alias(tmp_path) -> None:
    app_data_dir = tmp_path / "app"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps(
            {"device_id": "device-a", "alias": "Global Alias", "status": "active"}
        ),
        encoding="utf-8",
    )
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    store.write_frontier_alias("device-a", "Vault Alias")

    emitter = EventEmitter(store=store, app_data_dir=app_data_dir)
    event = emitter.emit_folder_create(
        _Entry(name="docs", node_id="folder-1", is_folder=True)
    )

    assert event.event_hash is not None
    assert store.read_frontier_record("device-a")["alias"] == "Vault Alias"


def test_event_emitter_file_conflict_archive_includes_parent_node_id(tmp_path) -> None:
    app_data_dir = tmp_path / "app"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    vault_path = tmp_path / "vault"
    store = _store(vault_path)
    emitter = EventEmitter(store=store, app_data_dir=app_data_dir)

    parent = _Entry(name=".glyphweave_conflicts", node_id="conflicts", is_folder=True)
    child = _Entry(
        name="report.txt.conflict",
        node_id="node-1",
        parent=parent,
        file_entry=_FileEntry(),
    )

    event = emitter.emit_file_conflict_archive(
        child,
        child.file_entry,
        "report.txt.conflict",
        conflict_id="conflict-1",
        reason_code="deleted_parent_move",
        reason_text="File moved into a deleted parent",
        trigger_event_id="evt-1",
        trigger_event_type="file_move",
        trigger_device_id="device-b",
    )

    assert event.payload["parent_node_id"] == "conflicts"
