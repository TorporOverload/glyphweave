from __future__ import annotations

import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.common.device_id import load_device_id
from app.common.logging import logger
from app.infrastructure.persistence.event_store import EventStore
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.hlc import HLCClock, compare_hlc
from app.core.domain.sync.models import HybridLogicalClock, VaultEvent
from app.services.sync.event_processor import EventProcessor
from app.services.sync.replay import refresh_replay_checkpoint

if TYPE_CHECKING:
    from sqlalchemy.orm import sessionmaker


class EventEmitter:
    """Emit local vault mutations into the append-only event store."""

    def __init__(
        self,
        store: EventStore,
        app_data_dir: Path,
        *,
        session_factory: "sessionmaker | None" = None,
        local_data_path: Path | None = None,
    ) -> None:
        self._store = store
        self._device_id = load_device_id(app_data_dir)
        self._clock = HLCClock(device_id=self._device_id)
        self._session_factory = session_factory
        self._local_data_path = local_data_path
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

    def emit_file_conflict_archive(
        self,
        file_ref: Any,
        file_entry: Any,
        archived_name: str,
        *,
        conflict_id: str,
        reason_code: str,
        reason_text: str,
        trigger_event_id: str,
        trigger_event_type: str,
        trigger_device_id: str,
        trigger_event_hash: str | None = None,
    ) -> VaultEvent:
        payload = {
            "conflict_id": conflict_id,
            "node_id": file_ref.node_id,
            "file_id": file_entry.file_id,
            "parent_node_id": file_ref.parent.node_id if file_ref.parent else None,
            "name": archived_name,
            "archived_name": archived_name,
            "blob_ids": [blob.blob_id for blob in getattr(file_entry, "blobs", [])],
            "content_hash": file_entry.content_hash,
            "mime_type": file_entry.mime_type,
            "file_size_bytes": file_entry.original_size_bytes,
            "encrypted_size_bytes": file_entry.encrypted_size_bytes,
            "metadata_json": file_entry.metadata_json,
            "reason_code": reason_code,
            "reason_text": reason_text,
            "trigger_event_id": trigger_event_id,
            "trigger_event_hash": trigger_event_hash,
            "trigger_event_type": trigger_event_type,
            "trigger_device_id": trigger_device_id,
            "origin_device_id": self._device_id,
        }
        return self._append(EventType.FILE_CONFLICT_ARCHIVE, payload)

    def emit_file_conflict_resolved(
        self,
        *,
        conflict_id: str,
        node_id: str,
        resolution_status: str = "deleted",
        resolution_reason: str = "explicit_delete",
    ) -> VaultEvent:
        payload = {
            "conflict_id": conflict_id,
            "node_id": node_id,
            "resolution_status": resolution_status,
            "resolution_reason": resolution_reason,
            "origin_device_id": self._device_id,
        }
        return self._append(EventType.FILE_CONFLICT_RESOLVED, payload)

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

    def emit_folder_conflict_archive(
        self,
        folder_ref: Any,
        archived_name: str,
        *,
        conflict_id: str,
        reason_code: str,
        reason_text: str,
        trigger_event_id: str,
        trigger_event_type: str,
        trigger_device_id: str,
        trigger_event_hash: str | None = None,
    ) -> VaultEvent:
        payload = {
            "conflict_id": conflict_id,
            "node_id": folder_ref.node_id,
            "name": archived_name,
            "archived_name": archived_name,
            "reason_code": reason_code,
            "reason_text": reason_text,
            "trigger_event_id": trigger_event_id,
            "trigger_event_hash": trigger_event_hash,
            "trigger_event_type": trigger_event_type,
            "trigger_device_id": trigger_device_id,
            "origin_device_id": self._device_id,
        }
        return self._append(EventType.FOLDER_CONFLICT_ARCHIVE, payload)

    def emit_folder_conflict_resolved(
        self,
        *,
        conflict_id: str,
        node_id: str,
        resolution_status: str = "deleted",
        resolution_reason: str = "explicit_delete",
    ) -> VaultEvent:
        payload = {
            "conflict_id": conflict_id,
            "node_id": node_id,
            "resolution_status": resolution_status,
            "resolution_reason": resolution_reason,
            "origin_device_id": self._device_id,
        }
        return self._append(EventType.FOLDER_CONFLICT_RESOLVED, payload)

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
        stored = self._store.append_event(event)
        self._process_local_event(stored)
        return stored

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

    def _process_local_event(self, event: VaultEvent) -> None:
        if self._session_factory is None:
            return

        try:
            result = EventProcessor(self._session_factory).process_event(event)
            logger.debug(
                "Processed locally emitted event %s with status=%s",
                event.event_id,
                result.status.value,
            )
            refresh_replay_checkpoint(
                store=self._store,
                session_factory=self._session_factory,
                local_data_path=self._local_data_path,
            )
        except Exception:
            logger.exception(
                "Failed to process locally emitted event %s; it will replay later",
                event.event_id,
            )
