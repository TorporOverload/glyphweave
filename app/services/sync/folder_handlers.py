from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.domain.sync.models import (
    FolderCreateData,
    FolderDeleteData,
    FolderMoveData,
    HybridLogicalClock,
    ProcessingResult,
    ProcessingStatus,
    VaultEvent,
)
from app.infrastructure.persistence.db.model.file_reference import FileReference

CONFLICT_FOLDER_NAME = ".glyphweave_conflicts"


def handle_folder_create(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FolderCreateData.from_dict(event.payload)
    existing_ref = processor._get_ref_by_node_id(session, parsed.node_id)
    if existing_ref is not None:
        current_structural_hlc = processor._structural_hlc_for_node(
            session, parsed.node_id
        )
        if processor._is_stale_event(event.hlc, current_structural_hlc):
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_DUPLICATE,
                message="Stale folder_create event",
                affected_ids=[existing_ref.id],
            )
        processor._upsert_sync_state(
            session, parsed.node_id, event.hlc, True, False, event.event_id
        )
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_IDEMPOTENT,
            message="Folder node already exists",
            affected_ids=[existing_ref.id],
        )

    if processor._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Folder node already deleted by a newer event",
        )

    parent = processor._resolve_parent_for_add(
        session, parsed.parent_node_id, event.hlc
    )
    folder_ref = FileReference(
        node_id=parsed.node_id,
        parent=parent,
        name=parsed.name,
        is_folder=True,
        file_entry_id=None,
    )
    session.add(folder_ref)
    session.flush()
    conflict_archived = False
    if parent is not None and parent.name == CONFLICT_FOLDER_NAME:
        folder_ref.name = processor._conflict_name(folder_ref.name, event.hlc)
        session.flush()
        conflict_archived = True
    processor._upsert_sync_state(
        session, parsed.node_id, event.hlc, True, False, event.event_id
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
            "Folder archived to conflict folder"
            if conflict_archived
            else "Folder created"
        ),
        affected_ids=[folder_ref.id],
    )


def handle_folder_move(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FolderMoveData.from_dict(event.payload)
    if processor._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Folder move is older than a delete tombstone",
        )
    if processor._is_stale_event(
        event.hlc, processor._structural_hlc_for_node(session, parsed.node_id)
    ):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Stale folder_move event",
        )
    folder_ref = processor._get_ref_by_node_id(session, parsed.node_id)
    if folder_ref is None or not folder_ref.is_folder:
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.FAILED,
            message="Folder node not found",
        )

    parent = processor._get_parent_ref(session, parsed.new_parent_node_id)
    folder_ref.parent = parent
    folder_ref.name = parsed.new_name
    session.flush()
    processor._upsert_sync_state(
        session, parsed.node_id, event.hlc, True, False, event.event_id
    )
    return ProcessingResult(
        event_id=event.event_id,
        event_type=event.type.value,
        status=ProcessingStatus.SUCCESS,
        message="Folder moved",
        affected_ids=[folder_ref.id],
    )


def handle_folder_delete(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FolderDeleteData.from_dict(event.payload)
    if processor._is_stale_event(
        event.hlc, processor._structural_hlc_for_node(session, parsed.node_id)
    ):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Stale folder_delete event",
        )
    if processor._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Folder already deleted by a newer event",
        )
    folder_ref = processor._get_ref_by_node_id(session, parsed.node_id)
    if folder_ref is None:
        processor._record_tombstone(session, parsed.node_id, "folder", event)
        processor._upsert_sync_state(
            session, parsed.node_id, event.hlc, True, False, event.event_id
        )
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_IDEMPOTENT,
            message="Folder already deleted",
        )

    affected_ids = delete_folder_subtree(session, folder_ref)
    processor._record_tombstone(session, parsed.node_id, "folder", event)
    processor._upsert_sync_state(
        session, parsed.node_id, event.hlc, True, False, event.event_id
    )
    return ProcessingResult(
        event_id=event.event_id,
        event_type=event.type.value,
        status=ProcessingStatus.SUCCESS,
        message="Folder deleted",
        affected_ids=affected_ids,
    )


def handle_db_dump_created(
    _processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    del session
    return ProcessingResult(
        event_id=event.event_id,
        event_type=event.type.value,
        status=ProcessingStatus.SUCCESS,
        message="DB dump event recorded",
    )


def delete_folder_subtree(session: Session, folder_ref: FileReference) -> list[int]:
    descendant_refs = session.scalars(
        select(FileReference).where(
            FileReference.virtual_path.like(folder_ref.virtual_path + "/%")
        )
    ).all()
    affected_ids = [folder_ref.id, *[ref.id for ref in descendant_refs]]
    for descendant in descendant_refs:
        session.delete(descendant)
    session.delete(folder_ref)
    session.flush()
    return affected_ids


def get_or_create_conflict_folder(session: Session) -> FileReference:
    conflict = session.scalar(
        select(FileReference).where(
            FileReference.parent_id.is_(None),
            FileReference.is_folder.is_(True),
            FileReference.name == CONFLICT_FOLDER_NAME,
        )
    )
    if conflict is not None:
        return conflict

    conflict = FileReference(
        name=CONFLICT_FOLDER_NAME,
        is_folder=True,
        file_entry_id=None,
    )
    session.add(conflict)
    session.flush()
    return conflict


def conflict_name(name: str, hlc: HybridLogicalClock) -> str:
    return f"{name}.conflict.{hlc.wall_time}.{hlc.logical}.{hlc.device_id}"
