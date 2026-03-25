from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.infrastructure.persistence.db.model.processed_event import ProcessedEvent
from app.infrastructure.persistence.db.service.session import session_scope
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import FileAddData, FileUpdateData
from app.services.sync.event_processor import EventProcessor
from app.infrastructure.persistence.event_store import EventStore
from app.core.domain.sync.hlc import hlc_to_tuple
from app.core.domain.sync.models import BatchProcessingResult, DiscoveredEvent
from app.common.paths.vault_layout import resolve_blob_path
from app.common.logging import logger


def replay_vault_events(
    *,
    session_factory: sessionmaker,
    vault_path: Path,
    store: EventStore,
) -> BatchProcessingResult:
    """Discover, sort, and apply immutable vault events."""
    processed_hashes = _load_processed_event_hashes(session_factory)
    discovered = store.discover_events(skip_hashes=processed_hashes)
    discovered = [
        item for item in discovered if is_event_ready_for_replay(vault_path, item)
    ]
    ordered = sorted(discovered, key=_sort_key)
    processor = EventProcessor(session_factory)
    result = processor.process_batch(ordered)
    logger.info(
        "Event replay completed: total=%s successful=%s"
        " skipped=%s failed=%s conflicts=%s",
        result.total,
        result.successful,
        result.skipped,
        result.failed,
        result.conflicts,
    )
    return result


def _sort_key(discovered: DiscoveredEvent) -> tuple[int, int, str, str]:
    event = discovered.event
    wall_time, logical, device_id = hlc_to_tuple(event.hlc.to_dict())
    return (wall_time, logical, device_id, event.event_id)


def _load_processed_event_hashes(session_factory: sessionmaker) -> set[str]:
    with session_scope(session_factory, commit=False) as session:
        hashes = session.scalars(select(ProcessedEvent.event_hash)).all()
    return {event_hash for event_hash in hashes if event_hash}


def is_event_ready_for_replay(vault_path: Path, discovered: DiscoveredEvent) -> bool:
    event = discovered.event
    if event.type == EventType.FILE_ADD:
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
