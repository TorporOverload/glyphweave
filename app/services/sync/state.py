from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.domain.sync.hlc import compare_hlc
from app.core.domain.sync.models import HybridLogicalClock, ProcessingResult, VaultEvent
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.model.processed_event import ProcessedEvent
from app.infrastructure.persistence.db.model.sync_node_state import SyncNodeState
from app.infrastructure.persistence.db.model.sync_tombstone import SyncTombstone


@dataclass(frozen=True)
class HLCFields:
    wall_time: int
    logical: int
    device_id: str


def get_ref_by_node_id(session: Session, node_id: str) -> FileReference | None:
    return session.scalar(select(FileReference).where(FileReference.node_id == node_id))


def get_parent_ref(
    processor, session: Session, parent_node_id: str | None
) -> FileReference | None:
    if parent_node_id is None:
        return None
    parent = get_ref_by_node_id(session, parent_node_id)
    if parent is None:
        raise ValueError(f"Parent node not found: {parent_node_id}")
    return parent


def resolve_parent_for_add(
    processor,
    session: Session,
    parent_node_id: str | None,
    event_hlc: HybridLogicalClock,
) -> FileReference | None:
    if parent_node_id is None:
        return None
    parent = get_ref_by_node_id(session, parent_node_id)
    if parent is not None:
        return parent
    tombstone = session.scalar(
        select(SyncTombstone).where(SyncTombstone.node_id == parent_node_id)
    )
    if tombstone is not None:
        tombstone_hlc = {
            "wall_time": tombstone.hlc_wall_time,
            "logical": tombstone.hlc_logical,
            "device_id": tombstone.hlc_device_id,
        }
        if compare_hlc(event_hlc.to_dict(), tombstone_hlc) > 0:
            return processor._get_or_create_conflict_folder(session)
    raise ValueError(f"Parent node not found: {parent_node_id}")


def record_processed_event(
    session: Session,
    event: VaultEvent,
    event_hash: str,
    result: ProcessingResult,
) -> None:
    session.add(
        ProcessedEvent(
            event_id=event.event_id,
            event_hash=event_hash,
            event_type=event.type.value,
            device_id=event.device_id,
            hlc_wall_time=event.hlc.wall_time,
            hlc_logical=event.hlc.logical,
            hlc_device_id=event.hlc.device_id,
            status=result.status.value,
            message=result.message,
        )
    )


def structural_hlc_for_node(session: Session, node_id: str) -> HLCFields | None:
    state = session.scalar(
        select(SyncNodeState).where(SyncNodeState.node_id == node_id)
    )
    if (
        state is None
        or state.last_structural_hlc_wall_time is None
        or state.last_structural_hlc_logical is None
        or state.last_structural_hlc_device_id is None
    ):
        return None
    return HLCFields(
        wall_time=state.last_structural_hlc_wall_time,
        logical=state.last_structural_hlc_logical,
        device_id=state.last_structural_hlc_device_id,
    )


def content_hlc_for_node(session: Session, node_id: str) -> HLCFields | None:
    state = session.scalar(
        select(SyncNodeState).where(SyncNodeState.node_id == node_id)
    )
    if (
        state is None
        or state.last_content_hlc_wall_time is None
        or state.last_content_hlc_logical is None
        or state.last_content_hlc_device_id is None
    ):
        return None
    return HLCFields(
        wall_time=state.last_content_hlc_wall_time,
        logical=state.last_content_hlc_logical,
        device_id=state.last_content_hlc_device_id,
    )


def is_stale_event(
    incoming_hlc: HybridLogicalClock, current_hlc: HLCFields | None
) -> bool:
    if current_hlc is None:
        return False
    return (
        compare_hlc(
            incoming_hlc.to_dict(),
            {
                "wall_time": current_hlc.wall_time,
                "logical": current_hlc.logical,
                "device_id": current_hlc.device_id,
            },
        )
        <= 0
    )


def is_deleted_after_or_equal(
    session: Session,
    node_id: str,
    incoming_hlc: HybridLogicalClock,
) -> bool:
    tombstone = session.scalar(
        select(SyncTombstone).where(SyncTombstone.node_id == node_id)
    )
    if tombstone is None:
        return False
    return (
        compare_hlc(
            incoming_hlc.to_dict(),
            {
                "wall_time": tombstone.hlc_wall_time,
                "logical": tombstone.hlc_logical,
                "device_id": tombstone.hlc_device_id,
            },
        )
        <= 0
    )


def upsert_sync_state(
    session: Session,
    node_id: str,
    hlc: HybridLogicalClock,
    structural: bool,
    content: bool,
    event_id: str,
) -> None:
    state = session.scalar(
        select(SyncNodeState).where(SyncNodeState.node_id == node_id)
    )
    if state is None:
        state = SyncNodeState(node_id=node_id)
        session.add(state)

    if structural:
        state.last_structural_hlc_wall_time = hlc.wall_time
        state.last_structural_hlc_logical = hlc.logical
        state.last_structural_hlc_device_id = hlc.device_id
    if content:
        state.last_content_hlc_wall_time = hlc.wall_time
        state.last_content_hlc_logical = hlc.logical
        state.last_content_hlc_device_id = hlc.device_id
    state.last_event_id = event_id
    state.updated_at = datetime.now(timezone.utc)
    session.flush()


def record_tombstone(
    session: Session,
    node_id: str,
    node_kind: str,
    event: VaultEvent,
) -> None:
    existing = session.scalar(
        select(SyncTombstone).where(SyncTombstone.node_id == node_id)
    )
    if existing is None:
        existing = SyncTombstone(node_id=node_id, node_kind=node_kind)
        session.add(existing)

    current_hlc = {
        "wall_time": existing.hlc_wall_time or 0,
        "logical": existing.hlc_logical or 0,
        "device_id": existing.hlc_device_id or "",
    }
    if (
        existing.event_id is not None
        and compare_hlc(event.hlc.to_dict(), current_hlc) <= 0
    ):
        return

    existing.node_kind = node_kind
    existing.event_id = event.event_id
    existing.device_id = event.device_id
    existing.hlc_wall_time = event.hlc.wall_time
    existing.hlc_logical = event.hlc.logical
    existing.hlc_device_id = event.hlc.device_id
    session.flush()
