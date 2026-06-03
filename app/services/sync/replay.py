from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

if TYPE_CHECKING:
    from collections.abc import Callable

    from app.services.sync.event_emitter import (
        FileEntryLike,
        FileRefLike,
        FolderRefLike,
    )

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.common.atomic_write import atomic_write_text
from app.common.logging import logger
from app.common.paths.runtime_layout import replay_checkpoint_path
from app.common.paths.vault_layout import resolve_blob_path
from app.infrastructure.persistence.db.model.processed_event import ProcessedEvent
from app.infrastructure.persistence.db.service.session import session_scope
from app.infrastructure.persistence.db.service.sync_conflict_service import (
    resolve_active_sync_conflicts_for_node_ids,
)
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import (
    FileAddData,
    FileConflictArchiveData,
    FileUpdateData,
)
from app.core.domain.sync.hlc import hlc_to_tuple
from app.core.domain.sync.models import BatchProcessingResult, DiscoveredEvent
from app.infrastructure.persistence.event_store import EventStore
from app.services.sync.event_processor import EventProcessor
from app.services.sync.state import (
    is_conflict_path as _is_conflict_path,
    local_resolution_event_id as _local_resolution_event_id,
)


class ReplayableStore(Protocol):
    """Minimal read-only interface required by replay_vault_events."""

    def discover_events(
        self,
        *,
        skip_hashes: set[str] | None = None,
    ) -> list[DiscoveredEvent]: ...

    def iter_frontier_hashes(self) -> set[str]: ...

    def has_unprocessed_events(
        self,
        *,
        skip_hashes: set[str] | None = None,
    ) -> bool: ...


@dataclass
class _BlobSnapshot:
    blob_id: str


@dataclass
class _FileEntrySnapshot:
    file_id: str
    content_hash: str
    mime_type: str
    original_size_bytes: int
    encrypted_size_bytes: int
    metadata_json: str | None
    blobs: list[_BlobSnapshot] = field(default_factory=list)


@dataclass
class _ParentSnapshot:
    node_id: str


@dataclass
class _FileRefSnapshot:
    node_id: str
    name: str
    parent: _ParentSnapshot | None
    file_entry: _FileEntrySnapshot | None = None


def replay_vault_events(
    *,
    session_factory: sessionmaker,
    vault_path: Path,
    store: ReplayableStore,
    local_data_path: Path | None = None,
    app_data_dir: Path | None = None,
    progress_callback: "Callable[[int, int, str], None] | None" = None,
) -> BatchProcessingResult:
    """Discover, sort, and apply immutable vault events."""
    processed_hashes = _load_processed_event_hashes(session_factory)
    current_frontier = store.iter_frontier_hashes()
    if _frontier_checkpoint_is_current(
        local_data_path=local_data_path,
        current_frontier=current_frontier,
        processed_hashes=processed_hashes,
    ):
        logger.info(
            "Event replay skipped: local checkpoint already matches "
            "current frontier (%s head(s))",
            len(current_frontier),
        )
        return BatchProcessingResult(
            total=0,
            successful=0,
            skipped=0,
            failed=0,
            conflicts=0,
            blocked=0,
            results=[],
        )

    discovered = store.discover_events(skip_hashes=processed_hashes)
    ordered, blocked = _partition_replayable_events(
        vault_path=vault_path,
        discovered=discovered,
        processed_hashes=processed_hashes,
    )
    processor = EventProcessor(session_factory)

    def _batch_progress(current: int, total: int) -> None:
        if progress_callback is not None:
            progress_callback(current, total, "Syncing…")

    result = processor.process_batch(
        ordered,
        progress_callback=_batch_progress if progress_callback else None,
    )
    if isinstance(store, EventStore):
        _emit_conflict_resolution_events(
            result,
            ordered,
            session_factory=session_factory,
            store=store,
            app_data_dir=app_data_dir,
            local_data_path=local_data_path,
        )
    current_frontier = store.iter_frontier_hashes()
    logger.info(
        "Event replay completed: total=%s successful=%s"
        " skipped=%s failed=%s conflicts=%s blocked=%s",
        result.total,
        result.successful,
        result.skipped,
        result.failed,
        result.conflicts,
        len(blocked),
    )
    result.blocked = len(blocked)
    _update_replay_checkpoint(
        local_data_path,
        current_frontier,
        session_factory,
        has_pending_events=bool(blocked),
    )
    return result


def refresh_replay_checkpoint(
    *,
    store: ReplayableStore,
    session_factory: sessionmaker,
    local_data_path: Path | None,
) -> None:
    """Refresh the local replay checkpoint from the store's current frontier."""
    processed_hashes = _load_processed_event_hashes(session_factory)
    _update_replay_checkpoint(
        local_data_path,
        store.iter_frontier_hashes(),
        session_factory,
        has_pending_events=store.has_unprocessed_events(skip_hashes=processed_hashes),
    )


def _emit_conflict_resolution_events(
    result: BatchProcessingResult,
    events: list[DiscoveredEvent],
    *,
    session_factory: sessionmaker,
    store: EventStore,
    app_data_dir: Path | None,
    local_data_path: Path | None,
) -> None:
    if app_data_dir is None:
        return

    from sqlalchemy.orm import joinedload

    from app.infrastructure.persistence.db.model.file_entry import FileEntry
    from app.infrastructure.persistence.db.model.file_reference import FileReference
    from app.infrastructure.persistence.db.model.sync_conflict import SyncConflict
    from app.services.sync.event_emitter import EventEmitter

    emitter = EventEmitter(
        store=store,
        app_data_dir=app_data_dir,
        session_factory=session_factory,
        local_data_path=local_data_path,
    )
    existing_archive_conflict_ids = {
        str(item.event.payload.get("conflict_id"))
        for item in events
        if item.event.type
        in {EventType.FILE_CONFLICT_ARCHIVE, EventType.FOLDER_CONFLICT_ARCHIVE}
        and item.event.payload.get("conflict_id")
    }

    for item in result.results:
        info = item.conflict_info or {}
        kind = info.get("kind")
        if kind not in {"file_conflict_archive", "folder_conflict_archive"}:
            continue

        conflict_id = info.get("conflict_id")
        trigger_device_id = info.get("trigger_device_id")
        if not conflict_id or not trigger_device_id:
            continue
        if str(conflict_id) in existing_archive_conflict_ids:
            continue

        with session_scope(session_factory) as session:
            existing_conflict = session.scalar(
                select(SyncConflict).where(SyncConflict.conflict_id == str(conflict_id))
            )
            if (
                existing_conflict is None
                or existing_conflict.status != "active"
                or existing_conflict.origin_device_id != str(trigger_device_id)
            ):
                continue

            file_ref = None
            if existing_conflict.archived_file_ref_id is not None:
                file_ref = session.scalar(
                    select(FileReference)
                    .options(
                        joinedload(FileReference.file_entry).joinedload(
                            FileEntry.blobs
                        ),
                        joinedload(FileReference.parent),
                    )
                    .where(FileReference.id == existing_conflict.archived_file_ref_id)
                )

            current_ref = session.scalar(
                select(FileReference).where(
                    FileReference.node_id == existing_conflict.node_id
                )
            )
            if file_ref is None:
                resolve_active_sync_conflicts_for_node_ids(
                    session,
                    node_ids=[existing_conflict.node_id],
                    resolution_event_id=_local_resolution_event_id(
                        existing_conflict.conflict_id,
                        "resolved" if current_ref is not None else "deleted",
                    ),
                    status="resolved" if current_ref is not None else "deleted",
                )
                continue
            if (
                file_ref.node_id != existing_conflict.node_id
                or file_ref.virtual_path != existing_conflict.archived_virtual_path
                or not _is_conflict_path(file_ref.virtual_path)
            ):
                resolve_active_sync_conflicts_for_node_ids(
                    session,
                    node_ids=[existing_conflict.node_id],
                    resolution_event_id=_local_resolution_event_id(
                        existing_conflict.conflict_id,
                        "resolved",
                    ),
                    status="resolved",
                )
                continue

            if file_ref.file_entry is None:
                if kind == "file_conflict_archive":
                    continue
                file_ref_payload = _FileRefSnapshot(
                    node_id=file_ref.node_id,
                    name=file_ref.name,
                    parent=_ParentSnapshot(node_id=file_ref.parent.node_id)
                    if file_ref.parent is not None
                    else None,
                )
            else:
                file_ref_payload = _FileRefSnapshot(
                    node_id=file_ref.node_id,
                    name=file_ref.name,
                    parent=_ParentSnapshot(node_id=file_ref.parent.node_id)
                    if file_ref.parent is not None
                    else None,
                    file_entry=_FileEntrySnapshot(
                        file_id=file_ref.file_entry.file_id,
                        blobs=[
                            _BlobSnapshot(blob_id=blob.blob_id)
                            for blob in file_ref.file_entry.blobs
                        ],
                        content_hash=file_ref.file_entry.content_hash,
                        mime_type=file_ref.file_entry.mime_type,
                        original_size_bytes=file_ref.file_entry.original_size_bytes,
                        encrypted_size_bytes=file_ref.file_entry.encrypted_size_bytes,
                        metadata_json=file_ref.file_entry.metadata_json,
                    ),
                )

            # Copy conflict fields while session is still open
            conflict_conflict_id = str(existing_conflict.conflict_id)
            conflict_archived_name = str(existing_conflict.archived_name)
            conflict_reason_code = str(existing_conflict.reason_code)
            conflict_reason_text = str(existing_conflict.reason_text)
            conflict_trigger_event_id = str(existing_conflict.trigger_event_id)
            conflict_trigger_event_type = str(existing_conflict.trigger_event_type)
            conflict_trigger_event_hash = (
                str(existing_conflict.trigger_event_hash)
                if existing_conflict.trigger_event_hash is not None
                else None
            )

        if kind == "file_conflict_archive":
            assert file_ref_payload.file_entry is not None
            emitter.emit_file_conflict_archive(
                cast("FileRefLike", file_ref_payload),
                cast("FileEntryLike", file_ref_payload.file_entry),
                conflict_archived_name,
                conflict_id=conflict_conflict_id,
                reason_code=conflict_reason_code,
                reason_text=conflict_reason_text,
                trigger_event_id=conflict_trigger_event_id,
                trigger_event_type=conflict_trigger_event_type,
                trigger_device_id=str(trigger_device_id),
                trigger_event_hash=conflict_trigger_event_hash,
            )
        else:
            emitter.emit_folder_conflict_archive(
                cast("FolderRefLike", file_ref_payload),
                conflict_archived_name,
                conflict_id=conflict_conflict_id,
                reason_code=conflict_reason_code,
                reason_text=conflict_reason_text,
                trigger_event_id=conflict_trigger_event_id,
                trigger_event_type=conflict_trigger_event_type,
                trigger_device_id=str(trigger_device_id),
                trigger_event_hash=conflict_trigger_event_hash,
            )


def _sort_key(discovered: DiscoveredEvent) -> tuple[int, int, str, str]:
    event = discovered.event
    wall_time, logical, device_id = hlc_to_tuple(event.hlc.to_dict())
    return (wall_time, logical, device_id, event.event_id)


def _partition_replayable_events(
    *,
    vault_path: Path,
    discovered: list[DiscoveredEvent],
    processed_hashes: set[str],
) -> tuple[list[DiscoveredEvent], list[DiscoveredEvent]]:
    ready_by_hash: dict[str, DiscoveredEvent] = {}
    pending_by_hash: dict[str, DiscoveredEvent] = {}
    for item in discovered:
        event_hash = _discovered_event_hash(item)
        if event_hash:
            pending_by_hash[event_hash] = item
        else:
            logger.warning(
                "Dropping event %s: no event_hash or source_path",
                item.event.event_id,
            )
    available_hashes = set(processed_hashes)

    progress = True
    while progress:
        progress = False
        for event_hash, item in list(pending_by_hash.items()):
            if not is_event_ready_for_replay(vault_path, item):
                continue
            if not all(parent in available_hashes for parent in item.event.parents):
                continue
            ready_by_hash[event_hash] = pending_by_hash.pop(event_hash)
            available_hashes.add(event_hash)
            progress = True

    ready = sorted(ready_by_hash.values(), key=_sort_key)
    blocked = sorted(pending_by_hash.values(), key=_sort_key)
    return ready, blocked


def _discovered_event_hash(discovered: DiscoveredEvent) -> str:
    event_hash = discovered.event.event_hash
    if event_hash:
        return str(event_hash)
    if discovered.source_path:
        return Path(discovered.source_path).stem
    return ""


def _load_processed_event_hashes(session_factory: sessionmaker) -> set[str]:
    with session_scope(session_factory, commit=False) as session:
        hashes = session.scalars(select(ProcessedEvent.event_hash)).all()
    return {event_hash for event_hash in hashes if event_hash}


def _frontier_checkpoint_is_current(
    *,
    local_data_path: Path | None,
    current_frontier: set[str],
    processed_hashes: set[str],
) -> bool:
    if local_data_path is None:
        return False

    checkpoint_frontier = _load_replay_checkpoint(local_data_path)
    if checkpoint_frontier is None:
        return False

    return checkpoint_frontier == current_frontier and current_frontier.issubset(
        processed_hashes
    )


def _load_replay_checkpoint(local_data_path: Path) -> set[str] | None:
    path = replay_checkpoint_path(local_data_path)
    if not path.exists():
        return None

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    frontier = payload.get("frontier")
    if not isinstance(frontier, list):
        return None
    return {str(item) for item in frontier if item}


def _write_replay_checkpoint(local_data_path: Path, frontier: set[str]) -> None:
    path = replay_checkpoint_path(local_data_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        path,
        json.dumps({"frontier": sorted(frontier)}, sort_keys=True, indent=2),
    )


def _clear_replay_checkpoint(local_data_path: Path) -> None:
    path = replay_checkpoint_path(local_data_path)
    try:
        path.unlink()
    except FileNotFoundError:
        return


def _update_replay_checkpoint(
    local_data_path: Path | None,
    current_frontier: set[str],
    session_factory: sessionmaker,
    *,
    has_pending_events: bool = False,
) -> None:
    if local_data_path is None:
        return

    if has_pending_events:
        _clear_replay_checkpoint(local_data_path)
        return

    processed_hashes = _load_processed_event_hashes(session_factory)
    if current_frontier.issubset(processed_hashes):
        _write_replay_checkpoint(local_data_path, current_frontier)
        return

    _clear_replay_checkpoint(local_data_path)


def is_event_ready_for_replay(vault_path: Path, discovered: DiscoveredEvent) -> bool:
    event = discovered.event
    if event.type == EventType.FILE_ADD:
        payload = FileAddData.from_dict(event.payload)
        return _all_blobs_exist(vault_path, payload.blob_ids)
    if event.type == EventType.FILE_CONFLICT_ARCHIVE:
        conflict_payload = FileConflictArchiveData.from_dict(event.payload)
        return _all_blobs_exist(vault_path, conflict_payload.blob_ids)
    if event.type == EventType.FILE_UPDATE:
        update_payload = FileUpdateData.from_dict(event.payload)
        return _all_blobs_exist(vault_path, update_payload.new_blob_ids)
    return True


def _all_blobs_exist(vault_path: Path, blob_ids: list[str]) -> bool:
    if not blob_ids:
        return True
    # When the blob storage directory does not exist at all, the vault is
    # either operating in DB-only mode (e.g. tests) or blob sync has not
    # started yet.  In both cases, allow replay so events are not blocked
    # indefinitely.  Once the directory *does* exist we require every
    # referenced blob to be present before replaying the event.
    if not resolve_blob_path(vault_path, blob_ids[0]).parent.exists():
        return True
    return all(resolve_blob_path(vault_path, blob_id).exists() for blob_id in blob_ids)
