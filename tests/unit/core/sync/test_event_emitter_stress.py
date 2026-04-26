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
    def __init__(self, file_id: str = "file-1") -> None:
        self.file_id = file_id
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


def test_rapid_sequential_event_emission(tmp_path) -> None:
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
    child2 = _Entry(
        name="notes.txt",
        node_id="node-2",
        parent=root,
        file_entry=_FileEntry(file_id="file-2"),
    )

    events = []
    folder_event = emitter.emit_folder_create(root)
    events.append(folder_event)

    file_event1 = emitter.emit_file_add(child)
    events.append(file_event1)

    file_event2 = emitter.emit_file_add(child2)
    events.append(file_event2)

    for event in events:
        assert event.event_hash is not None
        assert event.hlc is not None

    assert file_event1.parents == [folder_event.event_hash]
    assert file_event2.parents == [file_event1.event_hash]

    for i in range(len(events) - 1):
        curr_hlc = events[i].hlc
        next_hlc = events[i + 1].hlc
        assert (curr_hlc.wall_time, curr_hlc.logical) <= (
            next_hlc.wall_time,
            next_hlc.logical,
        )


def test_event_emitter_chains_frontier_correctly(tmp_path) -> None:
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

    frontier = store.read_frontier("device-a")
    assert frontier == [file_event.event_hash]

    assert file_event.parents == [folder_event.event_hash]
    assert folder_event.parents == []


def test_event_emitter_seeds_hlc_from_frontier_heads(
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


def test_event_emitter_preserves_existing_frontier_alias(tmp_path) -> None:
    app_data_dir = tmp_path / "app"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    vault_path = tmp_path / "vault"
    store = _store(vault_path)

    custom_alias = "my-custom-alias"
    store.write_frontier("device-a", [], alias=custom_alias)

    emitter = EventEmitter(store=store, app_data_dir=app_data_dir)
    local_event = emitter.emit_folder_create(
        _Entry(name="docs", node_id="folder-1", is_folder=True)
    )

    record = store.read_frontier_record("device-a")
    assert record.get("alias") == custom_alias
