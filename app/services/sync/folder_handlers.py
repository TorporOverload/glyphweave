from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.domain.sync.models import (
    FolderConflictArchiveData,
    FolderConflictResolvedData,
    FolderCreateData,
    FolderDeleteData,
    FolderMoveData,
    HybridLogicalClock,
    ProcessingResult,
    ProcessingStatus,
    VaultEvent,
)
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.service.sync_conflict_service import (
    resolve_active_sync_conflicts_for_node_ids,
    resolve_sync_conflict,
    upsert_sync_conflict,
)
from app.infrastructure.persistence.db.utils import (
    escape_like_pattern as _escape_like_pattern,
)
from app.services.sync.state import (
    ParentResolutionStatus,
    build_conflict_info_and_persist,
    is_conflict_path as _is_conflict_path,
)

CONFLICT_FOLDER_NAME = ".glyphweave_conflicts"


def handle_folder_create(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FolderCreateData.from_dict(event.payload)
    existing_ref = processor.get_ref_by_node_id(session, parsed.node_id)
    if existing_ref is not None:
        current_structural_hlc = processor.structural_hlc_for_node(
            session, parsed.node_id
        )
        if processor.is_stale_event(event.hlc, current_structural_hlc):
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_DUPLICATE,
                message="Stale folder_create event",
                affected_ids=[existing_ref.id],
            )
        processor.upsert_sync_state(
            session, parsed.node_id, event.hlc, True, False, event.event_id
        )
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_IDEMPOTENT,
            message="Folder node already exists",
            affected_ids=[existing_ref.id],
        )

    if processor.is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Folder node already deleted by a newer event",
        )

    resolution = processor.resolve_parent_for_add(
        session, parsed.parent_node_id, event.hlc
    )
    if resolution.status == ParentResolutionStatus.STALE_DELETED_PARENT:
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Folder create targets a parent deleted by a newer event",
        )
    if resolution.status == ParentResolutionStatus.MISSING_PARENT:
        raise ValueError(f"Invalid parent node: {parsed.parent_node_id}")

    parent = resolution.parent
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
    if resolution.status == ParentResolutionStatus.CONFLICT_ARCHIVE or (
        parent is not None and parent.name == CONFLICT_FOLDER_NAME
    ):
        folder_ref.name = processor.conflict_name(folder_ref.name, event.hlc)
        session.flush()
        conflict_archived = True
    processor.upsert_sync_state(
        session, parsed.node_id, event.hlc, True, False, event.event_id
    )
    conflict_info = (
        build_conflict_info_and_persist(
            session,
            ref=folder_ref,
            event=event,
            node_kind="folder",
            reason_code="deleted_parent_folder_create",
            reason_text=
            "Folder create targeted a parent folder that had already been deleted",
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
            "Folder archived to conflict folder"
            if conflict_archived
            else "Folder created"
        ),
        affected_ids=[folder_ref.id],
        conflict_info=conflict_info,
    )


def handle_folder_move(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FolderMoveData.from_dict(event.payload)
    if processor.is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Folder move is older than a delete tombstone",
        )
    if processor.is_stale_event(
        event.hlc, processor.structural_hlc_for_node(session, parsed.node_id)
    ):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Stale folder_move event",
        )
    folder_ref = processor.get_ref_by_node_id(session, parsed.node_id)
    if folder_ref is None or not folder_ref.is_folder:
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.FAILED,
            message="Folder node not found",
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
            message="Folder move targets a parent deleted by a newer event",
        )
    if resolution.status == ParentResolutionStatus.MISSING_PARENT:
        raise ValueError(f"Invalid parent node: {parsed.new_parent_node_id}")

    folder_ref.parent = resolution.parent
    folder_ref.name = parsed.new_name
    conflict_archived = False
    if resolution.status == ParentResolutionStatus.CONFLICT_ARCHIVE:
        folder_ref.name = processor.conflict_name(parsed.new_name, event.hlc)
        conflict_archived = True
    session.flush()
    if not conflict_archived and not _is_conflict_path(folder_ref.virtual_path):
        resolve_active_sync_conflicts_for_node_ids(
            session,
            node_ids=_subtree_node_ids(session, folder_ref),
            resolution_event_id=event.event_id,
            status="resolved",
        )
    processor.upsert_sync_state(
        session, parsed.node_id, event.hlc, True, False, event.event_id
    )
    conflict_info = (
        build_conflict_info_and_persist(
            session,
            ref=folder_ref,
            event=event,
            node_kind="folder",
            reason_code="deleted_parent_folder_move",
            reason_text=(
                "Folder move targeted a parent folder that had already been deleted"),
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
            "Folder move archived to conflict folder"
            if conflict_archived
            else "Folder moved"
        ),
        affected_ids=[folder_ref.id],
        conflict_info=conflict_info,
    )


def handle_folder_delete(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FolderDeleteData.from_dict(event.payload)
    if processor.is_stale_event(
        event.hlc, processor.structural_hlc_for_node(session, parsed.node_id)
    ):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Stale folder_delete event",
        )
    if processor.is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Folder already deleted by a newer event",
        )
    folder_ref = processor.get_ref_by_node_id(session, parsed.node_id)
    if folder_ref is None:
        resolve_active_sync_conflicts_for_node_ids(
            session,
            node_ids=[parsed.node_id],
            resolution_event_id=event.event_id,
            status="deleted",
        )
        processor.record_tombstone(session, parsed.node_id, "folder", event)
        processor.upsert_sync_state(
            session, parsed.node_id, event.hlc, True, False, event.event_id
        )
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_IDEMPOTENT,
            message="Folder already deleted",
        )

    resolve_active_sync_conflicts_for_node_ids(
        session,
        node_ids=_subtree_node_ids(session, folder_ref),
        resolution_event_id=event.event_id,
        status="deleted",
    )
    affected_ids = delete_folder_subtree(processor, session, folder_ref, event)
    processor.record_tombstone(session, parsed.node_id, "folder", event)
    processor.upsert_sync_state(
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


def handle_folder_conflict_archive(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FolderConflictArchiveData.from_dict(event.payload)
    if processor.is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Folder conflict archive is older than a newer delete tombstone",
        )
    if processor.is_stale_event(
        event.hlc, processor.structural_hlc_for_node(session, parsed.node_id)
    ):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Stale folder_conflict_archive event",
        )

    existing_ref = processor.get_ref_by_node_id(session, parsed.node_id)
    conflict_folder = processor.get_or_create_conflict_folder(session)
    if existing_ref is None:
        folder_ref = FileReference(
            node_id=parsed.node_id,
            parent=conflict_folder,
            name=parsed.archived_name,
            is_folder=True,
            file_entry_id=None,
        )
        session.add(folder_ref)
        session.flush()
    else:
        if not existing_ref.is_folder:
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.FAILED,
                message="Folder conflict archive targets a file node",
            )
        existing_ref.parent = conflict_folder
        existing_ref.name = parsed.archived_name
        session.flush()
        folder_ref = existing_ref

    upsert_sync_conflict(
        session,
        conflict_id=parsed.conflict_id,
        node_id=parsed.node_id,
        node_kind="folder",
        archived_name=folder_ref.name,
        archived_virtual_path=folder_ref.virtual_path,
        archived_file_ref_id=folder_ref.id,
        file_entry_id=None,
        reason_code=parsed.reason_code,
        reason_text=parsed.reason_text,
        trigger_event_id=parsed.trigger_event_id or event.event_id,
        trigger_event_hash=parsed.trigger_event_hash,
        trigger_event_type=parsed.trigger_event_type,
        origin_device_id=parsed.origin_device_id or event.device_id,
        status="active",
    )
    processor.upsert_sync_state(
        session, parsed.node_id, event.hlc, True, False, event.event_id
    )
    return ProcessingResult(
        event_id=event.event_id,
        event_type=event.type.value,
        status=ProcessingStatus.SUCCESS,
        message="Folder archived to shared conflict folder",
        affected_ids=[folder_ref.id],
    )


def handle_folder_conflict_resolved(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FolderConflictResolvedData.from_dict(event.payload)
    conflict = resolve_sync_conflict(
        session,
        conflict_id=parsed.conflict_id,
        resolution_event_id=event.event_id,
        status=parsed.resolution_status,
    )
    if conflict is None:
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_IDEMPOTENT,
            message="Sync conflict record already absent",
        )

    return ProcessingResult(
        event_id=event.event_id,
        event_type=event.type.value,
        status=ProcessingStatus.SUCCESS,
        message="Folder sync conflict resolved",
        affected_ids=[conflict.id],
    )


def delete_folder_subtree(
    processor,
    session: Session,
    folder_ref: FileReference,
    event: VaultEvent,
) -> list[int]:
    descendant_refs = session.scalars(
        select(FileReference).where(
            FileReference.virtual_path.like(
                _escape_like_pattern(folder_ref.virtual_path) + "/%",
                escape="\\",
            )
        )
    ).all()
    affected_ids = [folder_ref.id, *[ref.id for ref in descendant_refs]]
    descendant_tombstones = [
        (descendant.node_id, "folder" if descendant.is_folder else "file")
        for descendant in descendant_refs
    ]
    for descendant in descendant_refs:
        session.delete(descendant)
    session.delete(folder_ref)
    session.flush()
    for node_id, node_kind in descendant_tombstones:
        processor.record_tombstone(session, node_id, node_kind, event)
    return affected_ids


def _subtree_node_ids(session: Session, folder_ref: FileReference) -> list[str]:
    descendant_node_ids = session.scalars(
        select(FileReference.node_id).where(
            FileReference.virtual_path.like(
                _escape_like_pattern(folder_ref.virtual_path) + "/%",
                escape="\\",
            )
        )
    ).all()
    return [folder_ref.node_id, *[str(node_id) for node_id in descendant_node_ids]]


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


# Inverse of ``conflict_name``: a trailing ``.conflict.<wall>.<logical>.<device>``
# suffix, where wall/logical are integers and device is a dot-free id (uuid4).
_CONFLICT_SUFFIX_RE = re.compile(r"\.conflict\.\d+\.\d+\.[^.]+$")


def original_name(archived: str) -> str:
    """Recover the pre-conflict name from an archived entry name.

    Archiving renames an entry to ``<name>.conflict.<wall>.<logical>.<device>``
    so restoring it must strip that suffix, otherwise the restored file keeps a
    bogus extension (e.g. ``report.pdf.conflict.3000.0.<device-id>``). Names that
    don't carry a recognizable suffix are returned unchanged.
    """
    return _CONFLICT_SUFFIX_RE.sub("", archived)
