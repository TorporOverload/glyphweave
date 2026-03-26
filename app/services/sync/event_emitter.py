from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from app.common.device_id import load_device_id
from app.common.logging import logger
from app.infrastructure.persistence.event_store import EventStore
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.hlc import HLCClock, compare_hlc
from app.core.domain.sync.models import HybridLogicalClock, VaultEvent


class EventEmitter:
    """Emit local vault mutations into the append-only event store."""

    def __init__(self, store: EventStore, app_data_dir: Path) -> None:
        self._store = store
        self._device_id = load_device_id(app_data_dir)
        self._clock = HLCClock(device_id=self._device_id)
        self._observe_existing_events()

    def emit_file_add(self, file_ref: Any) -> VaultEvent:
        file_entry = file_ref.file_entry
        if file_entry is None:
            raise ValueError("file_ref.file_entry is required for file_add events")
        payload = {
            "node_id": file_ref.node_id,
            "file_id": file_entry.file_id,
            "parent_node_id": file_ref.parent.node_id if file_ref.parent else None,
            "name": file_ref.name,
            "blob_ids": [blob.blob_id for blob in getattr(file_entry, "blobs", [])],
            "content_hash": file_entry.content_hash,
            "mime_type": file_entry.mime_type,
            "file_size_bytes": file_entry.original_size_bytes,
            "encrypted_size_bytes": file_entry.encrypted_size_bytes,
            "metadata_json": file_entry.metadata_json,
        }
        return self._append(EventType.FILE_ADD, payload)

    def emit_file_update(
        self,
        file_ref: Any,
        old_entry: Any,
        new_entry: Any,
    ) -> VaultEvent:
        payload = {
            "node_id": file_ref.node_id,
            "old_file_id": old_entry.file_id if old_entry is not None else None,
            "new_file_id": new_entry.file_id,
            "old_blob_ids": [blob.blob_id for blob in getattr(old_entry, "blobs", [])],
            "new_blob_ids": [blob.blob_id for blob in getattr(new_entry, "blobs", [])],
            "old_content_hash": (
                old_entry.content_hash if old_entry is not None else None
            ),
            "new_content_hash": new_entry.content_hash,
            "new_file_size_bytes": new_entry.original_size_bytes,
            "new_encrypted_size_bytes": new_entry.encrypted_size_bytes,
            "new_metadata_json": new_entry.metadata_json,
        }
        return self._append(EventType.FILE_UPDATE, payload)

    def emit_file_move(
        self,
        file_ref: Any,
        *,
        new_parent_node_id: str | None,
        new_name: str,
    ) -> VaultEvent:
        payload = {
            "node_id": file_ref.node_id,
            "new_parent_node_id": new_parent_node_id,
            "new_name": new_name,
        }
        return self._append(EventType.FILE_MOVE, payload)

    def emit_file_delete(
        self,
        file_ref: Any,
        *,
        file_id: str | None = None,
    ) -> VaultEvent:
        payload = {
            "node_id": file_ref.node_id,
            "file_id": file_id,
            "reason": "user_action",
        }
        return self._append(EventType.FILE_DELETE, payload)

    def emit_folder_create(self, folder_ref: Any) -> VaultEvent:
        payload = {
            "node_id": folder_ref.node_id,
            "parent_node_id": folder_ref.parent.node_id if folder_ref.parent else None,
            "name": folder_ref.name,
        }
        return self._append(EventType.FOLDER_CREATE, payload)

    def emit_folder_move(
        self,
        folder_ref: Any,
        *,
        new_parent_node_id: str | None,
        new_name: str,
    ) -> VaultEvent:
        payload = {
            "node_id": folder_ref.node_id,
            "new_parent_node_id": new_parent_node_id,
            "new_name": new_name,
        }
        return self._append(EventType.FOLDER_MOVE, payload)

    def emit_folder_delete(
        self,
        folder_ref: Any,
        *,
        cascade: bool = True,
    ) -> VaultEvent:
        payload = {
            "node_id": folder_ref.node_id,
            "cascade": cascade,
        }
        return self._append(EventType.FOLDER_DELETE, payload)

    def _append(self, event_type: EventType, payload: dict[str, Any]) -> VaultEvent:
        frontier = self._store.read_frontier(self._device_id)
        event = VaultEvent(
            event_id=str(uuid.uuid4()),
            type=event_type,
            device_id=self._device_id,
            hlc=self._next_hlc(),
            payload=payload,
            parents=frontier,
        )
        return self._store.append_event(event)

    def _next_hlc(self) -> HybridLogicalClock:
        wall_time, logical, device_id = self._clock.next()
        return HybridLogicalClock(
            wall_time=wall_time,
            logical=logical,
            device_id=device_id,
        )

    def _observe_existing_events(self) -> None:
        latest: dict[str, object] | None = None
        for event_hash in self._store.iter_frontier_hashes():
            try:
                event = self._store.load_event(event_hash)
            except FileNotFoundError:
                continue
            except Exception:
                logger.exception("Failed to read frontier head event %s", event_hash)
                continue
            candidate = event.hlc.to_dict()
            if latest is None or compare_hlc(candidate, latest) > 0:
                latest = candidate
        if latest is not None:
            self._clock.observe(latest)
