import json

import app.core.sync.hlc as hlc_module
from app.core.sync.event_store import EventStore
from app.core.sync.event_types import EventType
from app.core.sync.event_emitter import EventEmitter
from app.core.sync.models import HybridLogicalClock, VaultEvent


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


def test_event_emitter_writes_events_and_chains_frontier(tmp_path) -> None:
    app_data_dir = tmp_path / "app"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    vault_path = tmp_path / "vault"
    emitter = EventEmitter(vault_path=vault_path, app_data_dir=app_data_dir)

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


def test_event_emitter_observes_existing_remote_hlc_on_startup(monkeypatch, tmp_path) -> None:
    app_data_dir = tmp_path / "app"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    vault_path = tmp_path / "vault"
    store = EventStore(vault_path)
    remote_event = VaultEvent(
        event_id="evt-remote",
        type=EventType.FOLDER_CREATE,
        device_id="device-b",
        hlc=HybridLogicalClock(wall_time=2000, logical=4, device_id="device-b"),
        payload={"node_id": "remote-folder", "parent_node_id": None, "name": "shared"},
        parents=[],
    )
    store.append_event(remote_event)
    monkeypatch.setattr(hlc_module.time, "time", lambda: 1.0)

    emitter = EventEmitter(vault_path=vault_path, app_data_dir=app_data_dir)
    local_event = emitter.emit_folder_create(
        _Entry(name="docs", node_id="folder-1", is_folder=True)
    )

    assert local_event.hlc == HybridLogicalClock(
        wall_time=2000,
        logical=6,
        device_id="device-a",
    )
