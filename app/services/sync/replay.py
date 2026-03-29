from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.common.logging import logger
from app.common.paths.runtime_layout import replay_checkpoint_path
from app.common.paths.vault_layout import resolve_blob_path
from app.infrastructure.persistence.db.model.processed_event import ProcessedEvent
from app.infrastructure.persistence.db.service.session import session_scope
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import FileAddData, FileUpdateData
from app.core.domain.sync.hlc import hlc_to_tuple
from app.core.domain.sync.models import BatchProcessingResult, DiscoveredEvent
from app.infrastructure.persistence.event_store import EventStore
from app.services.sync.event_processor import EventProcessor


def replay_vault_events(
    *,
    session_factory: sessionmaker,
    vault_path: Path,
    store: EventStore,
    local_data_path: Path | None = None,
    app_data_dir: Path | None = None,
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
            results=[],
        )

    discovered = store.discover_events(skip_hashes=processed_hashes)
    discovered = [
        item for item in discovered if is_event_ready_for_replay(vault_path, item)
    ]
    ordered = sorted(discovered, key=_sort_key)
    processor = EventProcessor(session_factory)
    result = processor.process_batch(ordered)
    _emit_conflict_resolution_events(
        result,
        session_factory=session_factory,
        store=store,
        app_data_dir=app_data_dir,
        local_data_path=local_data_path,
    )
    current_frontier = store.iter_frontier_hashes()
    logger.info(
        "Event replay completed: total=%s successful=%s"
        " skipped=%s failed=%s conflicts=%s",
        result.total,
        result.successful,
        result.skipped,
        result.failed,
        result.conflicts,
    )
    _update_replay_checkpoint(local_data_path, current_frontier, session_factory)
    return result


def refresh_replay_checkpoint(
    *,
    store: EventStore,
    session_factory: sessionmaker,
    local_data_path: Path | None,
) -> None:
    """Refresh the local replay checkpoint from the store's current frontier."""
    _update_replay_checkpoint(
        local_data_path,
        store.iter_frontier_hashes(),
        session_factory,
    )


def _emit_conflict_resolution_events(
    result: BatchProcessingResult,
    *,
    session_factory: sessionmaker,
    store: EventStore,
    app_data_dir: Path | None,
    local_data_path: Path | None,
) -> None:
    if app_data_dir is None:
        return

    from types import SimpleNamespace

    from sqlalchemy.orm import joinedload

    from app.infrastructure.persistence.db.model.file_entry import FileEntry
    from app.infrastructure.persistence.db.model.file_reference import FileReference
    from app.services.sync.event_emitter import EventEmitter

    emitter = EventEmitter(
        store=store,
        app_data_dir=app_data_dir,
        session_factory=session_factory,
        local_data_path=local_data_path,
    )

    for item in result.results:
        info = item.conflict_info or {}
        if info.get("kind") != "file_conflict_archive":
            continue

        node_id = info.get("node_id")
        archived_name = info.get("archived_name")
        if not node_id or not archived_name:
            continue

        with session_scope(session_factory, commit=False) as session:
            file_ref = (
                session.query(FileReference)
                .options(
                    joinedload(FileReference.file_entry).joinedload(FileEntry.blobs),
                    joinedload(FileReference.parent),
                )
                .filter(FileReference.node_id == str(node_id))
                .first()
            )
            if file_ref is None or file_ref.file_entry is None:
                continue
            file_ref_payload = SimpleNamespace(
                node_id=file_ref.node_id,
                name=file_ref.name,
                parent=SimpleNamespace(node_id=file_ref.parent.node_id)
                if file_ref.parent is not None
                else None,
                file_entry=SimpleNamespace(
                    file_id=file_ref.file_entry.file_id,
                    blobs=[
                        SimpleNamespace(blob_id=blob.blob_id)
                        for blob in file_ref.file_entry.blobs
                    ],
                    content_hash=file_ref.file_entry.content_hash,
                    mime_type=file_ref.file_entry.mime_type,
                    original_size_bytes=file_ref.file_entry.original_size_bytes,
                    encrypted_size_bytes=file_ref.file_entry.encrypted_size_bytes,
                    metadata_json=file_ref.file_entry.metadata_json,
                ),
            )

        emitter.emit_file_conflict_archive(
            file_ref_payload,
            file_ref_payload.file_entry,
            str(archived_name),
        )


def _sort_key(discovered: DiscoveredEvent) -> tuple[int, int, str, str]:
    event = discovered.event
    wall_time, logical, device_id = hlc_to_tuple(event.hlc.to_dict())
    return (wall_time, logical, device_id, event.event_id)


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
    path.write_text(
        json.dumps({"frontier": sorted(frontier)}, sort_keys=True, indent=2),
        encoding="utf-8",
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
) -> None:
    if local_data_path is None:
        return

    processed_hashes = _load_processed_event_hashes(session_factory)
    if current_frontier.issubset(processed_hashes):
        _write_replay_checkpoint(local_data_path, current_frontier)
        return

    _clear_replay_checkpoint(local_data_path)


def is_event_ready_for_replay(vault_path: Path, discovered: DiscoveredEvent) -> bool:
    event = discovered.event
    if event.type in {EventType.FILE_ADD, EventType.FILE_CONFLICT_ARCHIVE}:
        payload = FileAddData.from_dict(event.payload)
        return _all_blobs_exist(vault_path, payload.blob_ids)
    if event.type == EventType.FILE_UPDATE:
        payload = FileUpdateData.from_dict(event.payload)
        return _all_blobs_exist(vault_path, payload.new_blob_ids)
    return True


def _all_blobs_exist(vault_path: Path, blob_ids: list[str]) -> bool:
    if not blob_ids:
        return True
    if not resolve_blob_path(vault_path, blob_ids[0]).parent.exists():
        return True
    return all(resolve_blob_path(vault_path, blob_id).exists() for blob_id in blob_ids)
