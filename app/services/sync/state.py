from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import uuid

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


class ParentResolutionStatus(str, Enum):
    FOUND = "found"
    CONFLICT_ARCHIVE = "conflict_archive"
    STALE_DELETED_PARENT = "stale_deleted_parent"
    MISSING_PARENT = "missing_parent"


@dataclass(frozen=True)
class ParentResolution:
    parent: FileReference | None
    status: ParentResolutionStatus


def build_conflict_id(node_id: str, reason_code: str, trigger_event_id: str) -> str:
    return str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"{node_id}:{reason_code}:{trigger_event_id}")
    )


def build_conflict_info_and_persist(
    session: Session,
    *,
    ref: FileReference,
    event: VaultEvent,
    node_kind: str,
    reason_code: str,
    reason_text: str,
    file_entry_id: int | None = None,
) -> dict:
    """Build a conflict info dict and persist a SyncConflict record.
    """
    from app.infrastructure.persistence.db.service.sync_conflict_service import (
        upsert_sync_conflict,
    )

    conflict_id = build_conflict_id(ref.node_id, reason_code, event.event_id)
    conflict_info = {
        "conflict_id": conflict_id,
        "kind": f"{node_kind}_conflict_archive",
        "node_id": ref.node_id,
        "archived_name": ref.name,
        "reason_code": reason_code,
        "reason_text": reason_text,
        "trigger_event_id": event.event_id,
        "trigger_event_hash": event.event_hash,
        "trigger_event_type": event.type.value,
        "trigger_device_id": event.device_id,
    }
    if file_entry_id is not None:
        conflict_info["file_entry_id"] = file_entry_id

    upsert_sync_conflict(
        session,
        conflict_id=str(conflict_id),
        node_id=ref.node_id,
        node_kind=node_kind,
        archived_name=ref.name,
        archived_virtual_path=ref.virtual_path,
        archived_file_ref_id=ref.id,
        file_entry_id=file_entry_id,
        reason_code=reason_code,
        reason_text=reason_text,
        trigger_event_id=event.event_id,
        trigger_event_hash=event.event_hash,
        trigger_event_type=event.type.value,
        origin_device_id=event.device_id,
    )
    return conflict_info


def get_ref_by_node_id(session: Session, node_id: str) -> FileReference | None:
    return session.scalar(select(FileReference).where(FileReference.node_id == node_id))


def get_parent_ref(
    session: Session, parent_node_id: str | None
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
) -> ParentResolution:
    if parent_node_id is None:
        return ParentResolution(parent=None, status=ParentResolutionStatus.FOUND)
    parent = get_ref_by_node_id(session, parent_node_id)
    if parent is not None:
        return ParentResolution(parent=parent, status=ParentResolutionStatus.FOUND)
    tombstone = session.scalar(
        select(SyncTombstone).where(SyncTombstone.node_id == parent_node_id)
    )
    if tombstone is None:
        return ParentResolution(
            parent=None, status=ParentResolutionStatus.MISSING_PARENT
        )
    tombstone_hlc = {
        "wall_time": tombstone.hlc_wall_time,
        "logical": tombstone.hlc_logical,
        "device_id": tombstone.hlc_device_id,
    }
    if compare_hlc(event_hlc.to_dict(), tombstone_hlc) > 0:
        return ParentResolution(
            parent=processor.get_or_create_conflict_folder(session),
            status=ParentResolutionStatus.CONFLICT_ARCHIVE,
        )
    return ParentResolution(
        parent=None,
        status=ParentResolutionStatus.STALE_DELETED_PARENT,
    )


def resolve_parent_for_move(
    processor,
    session: Session,
    parent_node_id: str | None,
    event_hlc: HybridLogicalClock,
) -> ParentResolution:
    if parent_node_id is None:
        return ParentResolution(parent=None, status=ParentResolutionStatus.FOUND)

    parent = get_ref_by_node_id(session, parent_node_id)
    if parent is not None:
        return ParentResolution(parent=parent, status=ParentResolutionStatus.FOUND)

    tombstone = session.scalar(
        select(SyncTombstone).where(SyncTombstone.node_id == parent_node_id)
    )
    if tombstone is None:
        return ParentResolution(
            parent=None, status=ParentResolutionStatus.MISSING_PARENT
        )

    tombstone_hlc = {
        "wall_time": tombstone.hlc_wall_time,
        "logical": tombstone.hlc_logical,
        "device_id": tombstone.hlc_device_id,
    }
    if compare_hlc(event_hlc.to_dict(), tombstone_hlc) > 0:
        return ParentResolution(
            parent=processor.get_or_create_conflict_folder(session),
            status=ParentResolutionStatus.CONFLICT_ARCHIVE,
        )

    return ParentResolution(
        parent=None,
        status=ParentResolutionStatus.STALE_DELETED_PARENT,
    )


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


def local_resolution_event_id(conflict_id: str, resolution_status: str) -> str:
    """Build a deterministic event ID for a locally-initiated conflict resolution."""
    return f"local:{resolution_status}:{conflict_id}"


def is_conflict_path(virtual_path: str | None) -> bool:
    """Check whether a virtual path resides *under* the conflict folder.

    The trailing slash means only children are matched
    (e.g. ``/.glyphweave_conflicts/foo``), not the conflict folder itself.
    """
    from app.services.sync.folder_handlers import CONFLICT_FOLDER_NAME

    if not virtual_path:
        return False
    return virtual_path.startswith(f"/{CONFLICT_FOLDER_NAME}/")


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
