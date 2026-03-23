from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.domain.sync.models import (
    FileDeleteData,
    FileMoveData,
    ProcessingResult,
    ProcessingStatus,
    VaultEvent,
)


def handle_file_move(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FileMoveData.from_dict(event.payload)
    if processor._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="File move is older than a delete tombstone",
        )
    if processor._is_stale_event(
        event.hlc,
        processor._structural_hlc_for_node(session, parsed.node_id),
    ):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Stale file_move event",
        )
    file_ref = processor._get_ref_by_node_id(session, parsed.node_id)
    if file_ref is None or file_ref.is_folder:
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.FAILED,
            message="File node not found",
        )

    parent = processor._get_parent_ref(session, parsed.new_parent_node_id)
    file_ref.parent = parent
    file_ref.name = parsed.new_name
    session.flush()
    processor._upsert_sync_state(
        session, parsed.node_id, event.hlc, True, False, event.event_id
    )
    return ProcessingResult(
        event_id=event.event_id,
        event_type=event.type.value,
        status=ProcessingStatus.SUCCESS,
        message="File moved",
        affected_ids=[file_ref.id],
    )


def handle_file_delete(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FileDeleteData.from_dict(event.payload)
    if processor._is_stale_event(
        event.hlc,
        processor._structural_hlc_for_node(session, parsed.node_id),
    ):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Stale file_delete event",
        )
    if processor._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="File already deleted by a newer event",
        )
    file_ref = processor._get_ref_by_node_id(session, parsed.node_id)
    if file_ref is None:
        processor._record_tombstone(session, parsed.node_id, "file", event)
        processor._upsert_sync_state(
            session, parsed.node_id, event.hlc, True, True, event.event_id
        )
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_IDEMPOTENT,
            message="File already deleted",
        )

    ref_id = file_ref.id
    session.delete(file_ref)
    session.flush()
    processor._record_tombstone(session, parsed.node_id, "file", event)
    processor._upsert_sync_state(
        session, parsed.node_id, event.hlc, True, True, event.event_id
    )
    return ProcessingResult(
        event_id=event.event_id,
        event_type=event.type.value,
        status=ProcessingStatus.SUCCESS,
        message="File deleted",
        affected_ids=[ref_id],
    )
