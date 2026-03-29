from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.domain.sync.models import (
    FileAddData,
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

from .folder_handlers import CONFLICT_FOLDER_NAME
from .state import ParentResolutionStatus


def handle_file_add(processor, session: Session, event: VaultEvent) -> ProcessingResult:
    parsed = FileAddData.from_dict(event.payload)
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
                message="Stale file_add event",
                affected_ids=[existing_ref.id],
            )
        processor._upsert_sync_state(
            session, parsed.node_id, event.hlc, True, True, event.event_id
        )
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_IDEMPOTENT,
            message="File node already exists",
            affected_ids=[existing_ref.id],
        )

    if processor._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="File node already deleted by a newer event",
        )

    resolution = processor._resolve_parent_for_add(
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
        file_ref.name = processor._conflict_name(file_ref.name, event.hlc)
        session.flush()
        conflict_archived = True
    processor._upsert_sync_state(
        session, parsed.node_id, event.hlc, True, True, event.event_id
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
        conflict_info=(
            {
                "kind": "file_conflict_archive",
                "node_id": file_ref.node_id,
                "file_entry_id": file_ref.file_entry_id,
                "archived_name": file_ref.name,
            }
            if conflict_archived
            else None
        ),
    )


def handle_file_update(
    processor, session: Session, event: VaultEvent
) -> ProcessingResult:
    parsed = FileUpdateData.from_dict(event.payload)
    if processor._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="File update is older than a delete tombstone",
        )
    if processor._is_stale_event(
        event.hlc, processor._content_hlc_for_node(session, parsed.node_id)
    ):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Stale file_update event",
        )
    file_ref = processor._get_ref_by_node_id(session, parsed.node_id)
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

    file_ref.file_entry_id = file_entry.id
    file_ref.modified_at = datetime.now(timezone.utc)
    session.flush()
    processor._upsert_sync_state(
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
    parsed = FileAddData.from_dict(event.payload)
    if processor._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SKIPPED_DUPLICATE,
            message="Conflict archive is older than a newer delete tombstone",
        )

    existing_ref = processor._get_ref_by_node_id(session, parsed.node_id)
    conflict_folder = processor._get_or_create_conflict_folder(session)
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

    if existing_ref is None:
        file_ref = FileReference(
            node_id=parsed.node_id,
            parent=conflict_folder,
            name=parsed.name,
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
        existing_ref.name = parsed.name
        existing_ref.file_entry_id = file_entry.id
        existing_ref.modified_at = datetime.now(timezone.utc)
        session.flush()
        file_ref = existing_ref

    processor._upsert_sync_state(
        session, parsed.node_id, event.hlc, True, True, event.event_id
    )
    return ProcessingResult(
        event_id=event.event_id,
        event_type=event.type.value,
        status=ProcessingStatus.SUCCESS,
        message="File archived to shared conflict folder",
        affected_ids=[file_ref.id],
    )
