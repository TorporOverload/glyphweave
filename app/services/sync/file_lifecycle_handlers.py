from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.domain.sync.models import (
    FileDeleteData,
    FileMoveData,
    ProcessingResult,
    ProcessingStatus,
    VaultEvent,
)
from app.infrastructure.persistence.db.service.sync_conflict_service import (
    resolve_active_sync_conflicts_for_node_ids,
)
from app.services.sync.state import (
    ParentResolutionStatus,
    build_conflict_info_and_persist,
    is_conflict_path as _is_conflict_path,
)


def handle_file_move(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FileMoveData.from_dict(event.payload)
    if processor.is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="File move is older than a delete tombstone",
        )
    if processor.is_stale_event(
        event.hlc,
        processor.structural_hlc_for_node(session, parsed.node_id),
    ):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Stale file_move event",
        )
    file_ref = processor.get_ref_by_node_id(session, parsed.node_id)
    if file_ref is None or file_ref.is_folder:
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.FAILED,
            message="File node not found",
        )

    resolution = processor.resolve_parent_for_move(
        session,
        parsed.new_parent_node_id,
        event.hlc,
    )
    if resolution.status == ParentResolutionStatus.STALE_DELETED_PARENT:
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="File move targets a parent deleted by a newer event",
        )
    if resolution.status == ParentResolutionStatus.MISSING_PARENT:
        raise ValueError(f"Invalid parent node: {parsed.new_parent_node_id}")

    file_ref.parent = resolution.parent
    file_ref.name = parsed.new_name
    conflict_archived = False
    if resolution.status == ParentResolutionStatus.CONFLICT_ARCHIVE:
        file_ref.name = processor.conflict_name(parsed.new_name, event.hlc)
        conflict_archived = True
    session.flush()
    if not conflict_archived and not _is_conflict_path(file_ref.virtual_path):
        resolve_active_sync_conflicts_for_node_ids(
            session,
            node_ids=[parsed.node_id],
            resolution_event_id=event.event_id,
            status="resolved",
        )
    processor.upsert_sync_state(
        session, parsed.node_id, event.hlc, True, False, event.event_id
    )
    conflict_info = (
        build_conflict_info_and_persist(
            session,
            ref=file_ref,
            event=event,
            node_kind="file",
            reason_code="deleted_parent_move",
            reason_text=
            "File move targeted a parent folder that had already been deleted",
            file_entry_id=file_ref.file_entry_id,
        )
        if conflict_archived
        else None
    )
    return ProcessingResult(
        event_id=event.event_id,
        event_type=event.type.value,
        status=(
            ProcessingStatus.CONFLICT_ARCHIVED
            if conflict_archived
            else ProcessingStatus.SUCCESS
        ),
        message=(
            "File move archived to conflict folder"
            if conflict_archived
            else "File moved"
        ),
        affected_ids=[file_ref.id],
        conflict_info=conflict_info,
    )


def handle_file_delete(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FileDeleteData.from_dict(event.payload)
    if processor.is_stale_event(
        event.hlc,
        processor.structural_hlc_for_node(session, parsed.node_id),
    ):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Stale file_delete event",
        )
    if processor.is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="File already deleted by a newer event",
        )
    file_ref = processor.get_ref_by_node_id(session, parsed.node_id)
    if file_ref is None:
        resolve_active_sync_conflicts_for_node_ids(
            session,
            node_ids=[parsed.node_id],
            resolution_event_id=event.event_id,
            status="deleted",
        )
        processor.record_tombstone(session, parsed.node_id, "file", event)
        processor.upsert_sync_state(
            session, parsed.node_id, event.hlc, True, True, event.event_id
        )
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_IDEMPOTENT,
            message="File already deleted",
        )

    ref_id = file_ref.id
    resolve_active_sync_conflicts_for_node_ids(
        session,
        node_ids=[parsed.node_id],
        resolution_event_id=event.event_id,
        status="deleted",
    )
    session.delete(file_ref)
    session.flush()
    processor.record_tombstone(session, parsed.node_id, "file", event)
    processor.upsert_sync_state(
        session, parsed.node_id, event.hlc, True, True, event.event_id
    )
    return ProcessingResult(
        event_id=event.event_id,
        event_type=event.type.value,
        status=ProcessingStatus.SUCCESS,
        message="File deleted",
        affected_ids=[ref_id],
    )
