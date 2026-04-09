from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.common.logging import logger
from app.core.domain.sync.models import (
    FileAddData,
    FileConflictArchiveData,
    FileConflictResolvedData,
    FileUpdateData,
    ProcessingResult,
    ProcessingStatus,
    VaultEvent,
)
from app.infrastructure.persistence.db.model.file_blob_reference import (
    FileBlobReference,
)
from app.infrastructure.persistence.db.model.file_entry import FileEntry
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.service.sync_conflict_service import (
    resolve_sync_conflict,
    upsert_sync_conflict,
)

from .folder_handlers import CONFLICT_FOLDER_NAME
from .state import ParentResolutionStatus, build_conflict_info_and_persist


def handle_file_add(processor, session: Session, event: VaultEvent) -> ProcessingResult:
    parsed = FileAddData.from_dict(event.payload)
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
                message="Stale file_add event",
                affected_ids=[existing_ref.id],
            )
        processor.upsert_sync_state(
            session, parsed.node_id, event.hlc, True, True, event.event_id
        )
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_IDEMPOTENT,
            message="File node already exists",
            affected_ids=[existing_ref.id],
        )

    if processor.is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="File node already deleted by a newer event",
        )

    resolution = processor.resolve_parent_for_add(
        session, parsed.parent_node_id, event.hlc
    )
    if resolution.status == ParentResolutionStatus.STALE_DELETED_PARENT:
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="File add targets a parent deleted by a newer event",
        )
    if resolution.status == ParentResolutionStatus.MISSING_PARENT:
        raise ValueError(f"Invalid parent node: {parsed.parent_node_id}")

    parent = resolution.parent
    file_entry = session.scalar(
        select(FileEntry).where(FileEntry.content_hash == parsed.content_hash)
    )
    if file_entry is None:
        file_entry = FileEntry(
            file_id=parsed.file_id,
            content_hash=parsed.content_hash,
            mime_type=parsed.mime_type,
            encrypted_size_bytes=parsed.encrypted_size_bytes,
            original_size_bytes=parsed.file_size_bytes,
            metadata_json=parsed.metadata_json,
        )
        session.add(file_entry)
        session.flush()
        for index, blob_id in enumerate(parsed.blob_ids):
            session.add(
                FileBlobReference(
                    file_entry_id=file_entry.id,
                    blob_id=blob_id,
                    blob_index=index,
                )
            )
        session.flush()
    else:
        _ensure_blob_references(session, file_entry, parsed.blob_ids)

    file_ref = FileReference(
        node_id=parsed.node_id,
        parent=parent,
        name=parsed.name,
        is_folder=False,
        file_entry_id=file_entry.id,
    )
    session.add(file_ref)
    session.flush()
    conflict_archived = False
    if resolution.status == ParentResolutionStatus.CONFLICT_ARCHIVE or (
        parent is not None and parent.name == CONFLICT_FOLDER_NAME
    ):
        file_ref.name = processor.conflict_name(file_ref.name, event.hlc)
        session.flush()
        conflict_archived = True
    processor.upsert_sync_state(
        session, parsed.node_id, event.hlc, True, True, event.event_id
    )
    conflict_info = (
        build_conflict_info_and_persist(
            session,
            ref=file_ref,
            event=event,
            node_kind="file",
            reason_code="deleted_parent_add",
            reason_text=
            "File add targeted a parent folder that had already been deleted",
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
            "File archived to conflict folder" if conflict_archived else "File added"
        ),
        affected_ids=[file_ref.id],
        conflict_info=conflict_info,
    )


def handle_file_update(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FileUpdateData.from_dict(event.payload)
    if processor.is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="File update is older than a delete tombstone",
        )
    if processor.is_stale_event(
        event.hlc, processor.content_hlc_for_node(session, parsed.node_id)
    ):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Stale file_update event",
        )
    file_ref = processor.get_ref_by_node_id(session, parsed.node_id)
    if file_ref is None or file_ref.is_folder:
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.FAILED,
            message="File node not found",
        )

    file_entry = session.scalar(
        select(FileEntry).where(FileEntry.content_hash == parsed.new_content_hash)
    )
    if file_entry is None:
        file_entry = FileEntry(
            file_id=parsed.new_file_id,
            content_hash=parsed.new_content_hash,
            mime_type=(
                file_ref.file_entry.mime_type
                if file_ref.file_entry
                else "application/octet-stream"
            ),
            encrypted_size_bytes=parsed.new_encrypted_size_bytes,
            original_size_bytes=parsed.new_file_size_bytes,
            metadata_json=parsed.new_metadata_json,
        )
        session.add(file_entry)
        session.flush()
        for index, blob_id in enumerate(parsed.new_blob_ids):
            session.add(
                FileBlobReference(
                    file_entry_id=file_entry.id,
                    blob_id=blob_id,
                    blob_index=index,
                )
            )
        session.flush()
    else:
        _ensure_blob_references(session, file_entry, parsed.new_blob_ids)

    file_ref.file_entry_id = file_entry.id
    file_ref.modified_at = datetime.now(timezone.utc)
    session.flush()
    processor.upsert_sync_state(
        session, parsed.node_id, event.hlc, False, True, event.event_id
    )
    return ProcessingResult(
        event_id=event.event_id,
        event_type=event.type.value,
        status=ProcessingStatus.SUCCESS,
        message="File updated",
        affected_ids=[file_ref.id, file_entry.id],
    )


def handle_file_conflict_archive(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FileConflictArchiveData.from_dict(event.payload)
    if processor.is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Conflict archive is older than a newer delete tombstone",
        )
    structural_hlc = processor.structural_hlc_for_node(session, parsed.node_id)
    content_hlc = processor.content_hlc_for_node(session, parsed.node_id)
    if processor.is_stale_event(event.hlc, structural_hlc) or processor.is_stale_event(
        event.hlc, content_hlc
    ):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Stale file_conflict_archive event",
        )

    existing_ref = processor.get_ref_by_node_id(session, parsed.node_id)
    conflict_folder = processor.get_or_create_conflict_folder(session)
    file_entry = session.scalar(
        select(FileEntry).where(FileEntry.content_hash == parsed.content_hash)
    )
    if file_entry is None:
        file_entry = FileEntry(
            file_id=parsed.file_id,
            content_hash=parsed.content_hash,
            mime_type=parsed.mime_type,
            encrypted_size_bytes=parsed.encrypted_size_bytes,
            original_size_bytes=parsed.file_size_bytes,
            metadata_json=parsed.metadata_json,
        )
        session.add(file_entry)
        session.flush()
        for index, blob_id in enumerate(parsed.blob_ids):
            session.add(
                FileBlobReference(
                    file_entry_id=file_entry.id,
                    blob_id=blob_id,
                    blob_index=index,
                )
            )
        session.flush()
    else:
        _ensure_blob_references(session, file_entry, parsed.blob_ids)

    if existing_ref is None:
        file_ref = FileReference(
            node_id=parsed.node_id,
            parent=conflict_folder,
            name=parsed.archived_name,
            is_folder=False,
            file_entry_id=file_entry.id,
        )
        session.add(file_ref)
        session.flush()
    else:
        if existing_ref.is_folder:
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.FAILED,
                message="Conflict archive targets a folder node",
            )
        existing_ref.parent = conflict_folder
        existing_ref.name = parsed.archived_name
        existing_ref.file_entry_id = file_entry.id
        existing_ref.modified_at = datetime.now(timezone.utc)
        session.flush()
        file_ref = existing_ref

    upsert_sync_conflict(
        session,
        conflict_id=parsed.conflict_id,
        node_id=parsed.node_id,
        node_kind="file",
        archived_name=file_ref.name,
        archived_virtual_path=file_ref.virtual_path,
        archived_file_ref_id=file_ref.id,
        file_entry_id=file_entry.id,
        reason_code=parsed.reason_code,
        reason_text=parsed.reason_text,
        trigger_event_id=parsed.trigger_event_id or event.event_id,
        trigger_event_hash=parsed.trigger_event_hash,
        trigger_event_type=parsed.trigger_event_type,
        origin_device_id=parsed.origin_device_id or event.device_id,
        status="active",
    )

    processor.upsert_sync_state(
        session, parsed.node_id, event.hlc, True, True, event.event_id
    )
    return ProcessingResult(
        event_id=event.event_id,
        event_type=event.type.value,
        status=ProcessingStatus.SUCCESS,
        message="File archived to shared conflict folder",
        affected_ids=[file_ref.id],
    )


def handle_file_conflict_resolved(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FileConflictResolvedData.from_dict(event.payload)
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
        message="Sync conflict resolved",
        affected_ids=[conflict.id],
    )


def _ensure_blob_references(
    session: Session,
    file_entry: FileEntry,
    blob_ids: list[str],
) -> None:
    existing_by_index = {blob.blob_index: blob.blob_id for blob in file_entry.blobs}
    for index, blob_id in enumerate(blob_ids):
        existing_blob_id = existing_by_index.get(index)
        if existing_blob_id == blob_id:
            continue
        if existing_blob_id is not None:
            logger.warning(
                "Skipping alternate blob set for deduplicated file entry "
                "%s at chunk %s",
                file_entry.id,
                index,
            )
            return
        session.add(
            FileBlobReference(
                file_entry_id=file_entry.id,
                blob_id=blob_id,
                blob_index=index,
            )
        )
    session.flush()
