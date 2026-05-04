from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.infrastructure.persistence.db.base import Base
from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.infrastructure.persistence.event_store import EventStore
from app.infrastructure.persistence.event_store_config import EventStoreConfig
from app.services.sync.event_emitter import EventEmitter
from app.services.sync.replay import replay_vault_events

_MASTER_KEY = SecureMemory(b"k" * 32)


class _Blob:
    def __init__(self, blob_id: str) -> None:
        self.blob_id = blob_id


class _FileEntry:
    def __init__(
        self,
        *,
        file_id: str = "file-id-1",
        content_hash: str = "content-hash-1",
        blob_ids: list[str] | None = None,
    ) -> None:
        self.file_id = file_id
        self.content_hash = content_hash
        self.mime_type = "text/plain"
        self.original_size_bytes = 5
        self.encrypted_size_bytes = 21
        self.metadata_json = None
        self.blobs = [_Blob(b) for b in (blob_ids or [])]


class _Ref:
    def __init__(
        self,
        *,
        name: str,
        node_id: str,
        parent: _Ref | None = None,
        file_entry: _FileEntry | None = None,
        is_folder: bool = False,
    ) -> None:
        self.name = name
        self.node_id = node_id
        self.parent = parent
        self.file_entry = file_entry
        self.is_folder = is_folder


@dataclasses.dataclass
class DeviceCtx:
    device_id: str
    app_data_dir: Path
    vault_path: Path
    session_factory: sessionmaker
    store: EventStore
    emitter: EventEmitter

    def replay(self, *, local_data_path: Path | None = None):
        return replay_vault_events(
            session_factory=self.session_factory,
            vault_path=self.vault_path,
            store=self.store,
            local_data_path=local_data_path,
            app_data_dir=self.app_data_dir,
        )


def make_device(device_id: str, vault_path: Path, base_tmp: Path) -> DeviceCtx:
    app_data_dir = base_tmp / device_id
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps({"device_id": device_id, "name": device_id, "status": "active"}),
        encoding="utf-8",
    )
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    store = EventStore(
        EventStoreConfig(
            vault_path=vault_path,
            vault_id="test-vault",
            master_key=_MASTER_KEY,
            encryption_enabled=True,
        )
    )
    emitter = EventEmitter(store=store, app_data_dir=app_data_dir)
    return DeviceCtx(
        device_id=device_id,
        app_data_dir=app_data_dir,
        vault_path=vault_path,
        session_factory=factory,
        store=store,
        emitter=emitter,
    )
