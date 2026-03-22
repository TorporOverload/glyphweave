from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.database.model.file_blob_reference import FileBlobReference
from app.core.database.model.file_entry import FileEntry
from app.core.database.model.file_reference import FileReference
from app.core.database.model.processed_event import ProcessedEvent
from app.core.database.model.sync_node_state import SyncNodeState
from app.core.database.model.sync_tombstone import SyncTombstone
from app.core.database.service.session import session_scope
from app.core.sync.hashing import hash_event
from app.core.sync.hlc import compare_hlc
from app.core.sync.models import (
    BatchProcessingResult,
    DiscoveredEvent,
    FileAddData,
    FileDeleteData,
    FileMoveData,
    FileUpdateData,
    FolderCreateData,
    FolderDeleteData,
    FolderMoveData,
    HybridLogicalClock,
    ProcessingResult,
    ProcessingStatus,
    VaultEvent,
)

CONFLICT_FOLDER_NAME = ".glyphweave_conflicts"


@dataclass(frozen=True)
class _HLCFields:
    wall_time: int
    logical: int
    device_id: str


class EventProcessor:
    """Apply sync events transactionally to the local SQLCipher schema."""

    def __init__(self, session_factory: sessionmaker) -> None:
        self._session_factory = session_factory

    def process_event(self, event: VaultEvent) -> ProcessingResult:
        event_hash = event.event_hash or hash_event(event)
        with session_scope(self._session_factory) as session:
            existing = session.scalar(
                select(ProcessedEvent).where(ProcessedEvent.event_id == event.event_id)
            )
            if existing is not None:
                return ProcessingResult(
                    event_id=event.event_id,
                    event_type=event.type.value,
                    status=ProcessingStatus.SKIPPED_IDEMPOTENT,
                    message="Event already processed",
                )

            handler = getattr(self, f"_handle_{event.type.value}", None)
            if handler is None:
                result = ProcessingResult(
                    event_id=event.event_id,
                    event_type=event.type.value,
                    status=ProcessingStatus.FAILED,
                    message=f"Unsupported event type: {event.type.value}",
                )
            else:
                result = handler(session, event)

            self._record_processed_event(
                session=session,
                event=event,
                event_hash=event_hash,
                result=result,
            )
            return result

    def process_discovered_event(self, discovered: DiscoveredEvent) -> ProcessingResult:
        return self.process_event(discovered.event)

    def process_batch(self, events: list[DiscoveredEvent]) -> BatchProcessingResult:
        results = [self.process_discovered_event(event) for event in events]
        successful = sum(
            1
            for result in results
            if result.status
            in {
                ProcessingStatus.SUCCESS,
                ProcessingStatus.CONFLICT_RESOLVED,
                ProcessingStatus.CONFLICT_ARCHIVED,
            }
        )
        skipped = sum(
            1
            for result in results
            if result.status
            in {
                ProcessingStatus.SKIPPED_DUPLICATE,
                ProcessingStatus.SKIPPED_IDEMPOTENT,
            }
        )
        failed = sum(1 for result in results if result.status == ProcessingStatus.FAILED)
        conflicts = sum(
            1
            for result in results
            if result.status
            in {
                ProcessingStatus.CONFLICT_RESOLVED,
                ProcessingStatus.CONFLICT_ARCHIVED,
            }
        )
        return BatchProcessingResult(
            total=len(results),
            successful=successful,
            skipped=skipped,
            failed=failed,
            conflicts=conflicts,
            results=results,
        )

    def _handle_file_add(self, session: Session, event: VaultEvent) -> ProcessingResult:
        parsed = FileAddData.from_dict(event.payload)
        existing_ref = self._get_ref_by_node_id(session, parsed.node_id)
        if existing_ref is not None:
            current_structural_hlc = self._structural_hlc_for_node(session, parsed.node_id)
            if self._is_stale_event(event.hlc, current_structural_hlc):
                return ProcessingResult(
                    event_id=event.event_id,
                    event_type=event.type.value,
                    status=ProcessingStatus.SKIPPED_DUPLICATE,
                    message="Stale file_add event",
                    affected_ids=[existing_ref.id],
                )
            self._upsert_sync_state(
                session=session,
                node_id=parsed.node_id,
                hlc=event.hlc,
                structural=True,
                content=True,
                event_id=event.event_id,
            )
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_IDEMPOTENT,
                message="File node already exists",
                affected_ids=[existing_ref.id],
            )

        if self._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_DUPLICATE,
                message="File node already deleted by a newer event",
            )

        parent = self._resolve_parent_for_add(session, parsed.parent_node_id, event.hlc)
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
        if parent is not None and parent.name == CONFLICT_FOLDER_NAME:
            file_ref.name = self._conflict_name(file_ref.name, event.hlc)
            session.flush()
            conflict_archived = True
        self._upsert_sync_state(
            session=session,
            node_id=parsed.node_id,
            hlc=event.hlc,
            structural=True,
            content=True,
            event_id=event.event_id,
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
                "File archived to conflict folder"
                if conflict_archived
                else "File added"
            ),
            affected_ids=[file_ref.id],
        )

    def _handle_file_update(self, session: Session, event: VaultEvent) -> ProcessingResult:
        parsed = FileUpdateData.from_dict(event.payload)
        if self._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_DUPLICATE,
                message="File update is older than a delete tombstone",
            )
        if self._is_stale_event(
            event.hlc,
            self._content_hlc_for_node(session, parsed.node_id),
        ):
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_DUPLICATE,
                message="Stale file_update event",
            )
        file_ref = self._get_ref_by_node_id(session, parsed.node_id)
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
                mime_type=file_ref.file_entry.mime_type if file_ref.file_entry else "application/octet-stream",
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
        self._upsert_sync_state(
            session=session,
            node_id=parsed.node_id,
            hlc=event.hlc,
            structural=False,
            content=True,
            event_id=event.event_id,
        )
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SUCCESS,
            message="File updated",
            affected_ids=[file_ref.id, file_entry.id],
        )

    def _handle_file_move(self, session: Session, event: VaultEvent) -> ProcessingResult:
        parsed = FileMoveData.from_dict(event.payload)
        if self._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_DUPLICATE,
                message="File move is older than a delete tombstone",
            )
        if self._is_stale_event(
            event.hlc,
            self._structural_hlc_for_node(session, parsed.node_id),
        ):
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_DUPLICATE,
                message="Stale file_move event",
            )
        file_ref = self._get_ref_by_node_id(session, parsed.node_id)
        if file_ref is None or file_ref.is_folder:
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.FAILED,
                message="File node not found",
            )

        parent = self._get_parent_ref(session, parsed.new_parent_node_id)
        file_ref.parent = parent
        file_ref.name = parsed.new_name
        session.flush()
        self._upsert_sync_state(
            session=session,
            node_id=parsed.node_id,
            hlc=event.hlc,
            structural=True,
            content=False,
            event_id=event.event_id,
        )
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SUCCESS,
            message="File moved",
            affected_ids=[file_ref.id],
        )

    def _handle_file_delete(self, session: Session, event: VaultEvent) -> ProcessingResult:
        parsed = FileDeleteData.from_dict(event.payload)
        if self._is_stale_event(
            event.hlc,
            self._structural_hlc_for_node(session, parsed.node_id),
        ):
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_DUPLICATE,
                message="Stale file_delete event",
            )
        if self._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_DUPLICATE,
                message="File already deleted by a newer event",
            )
        file_ref = self._get_ref_by_node_id(session, parsed.node_id)
        if file_ref is None:
            self._record_tombstone(
                session=session,
                node_id=parsed.node_id,
                node_kind="file",
                event=event,
            )
            self._upsert_sync_state(
                session=session,
                node_id=parsed.node_id,
                hlc=event.hlc,
                structural=True,
                content=True,
                event_id=event.event_id,
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
        self._record_tombstone(
            session=session,
            node_id=parsed.node_id,
            node_kind="file",
            event=event,
        )
        self._upsert_sync_state(
            session=session,
            node_id=parsed.node_id,
            hlc=event.hlc,
            structural=True,
            content=True,
            event_id=event.event_id,
        )
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SUCCESS,
            message="File deleted",
            affected_ids=[ref_id],
        )

    def _handle_folder_create(self, session: Session, event: VaultEvent) -> ProcessingResult:
        parsed = FolderCreateData.from_dict(event.payload)
        existing_ref = self._get_ref_by_node_id(session, parsed.node_id)
        if existing_ref is not None:
            current_structural_hlc = self._structural_hlc_for_node(session, parsed.node_id)
            if self._is_stale_event(event.hlc, current_structural_hlc):
                return ProcessingResult(
                    event_id=event.event_id,
                    event_type=event.type.value,
                    status=ProcessingStatus.SKIPPED_DUPLICATE,
                    message="Stale folder_create event",
                    affected_ids=[existing_ref.id],
                )
            self._upsert_sync_state(
                session=session,
                node_id=parsed.node_id,
                hlc=event.hlc,
                structural=True,
                content=False,
                event_id=event.event_id,
            )
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_IDEMPOTENT,
                message="Folder node already exists",
                affected_ids=[existing_ref.id],
            )

        if self._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_DUPLICATE,
                message="Folder node already deleted by a newer event",
            )

        parent = self._resolve_parent_for_add(session, parsed.parent_node_id, event.hlc)
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
            folder_ref.name = self._conflict_name(folder_ref.name, event.hlc)
            session.flush()
            conflict_archived = True
        self._upsert_sync_state(
            session=session,
            node_id=parsed.node_id,
            hlc=event.hlc,
            structural=True,
            content=False,
            event_id=event.event_id,
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

    def _handle_folder_move(self, session: Session, event: VaultEvent) -> ProcessingResult:
        parsed = FolderMoveData.from_dict(event.payload)
        if self._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_DUPLICATE,
                message="Folder move is older than a delete tombstone",
            )
        if self._is_stale_event(
            event.hlc,
            self._structural_hlc_for_node(session, parsed.node_id),
        ):
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_DUPLICATE,
                message="Stale folder_move event",
            )
        folder_ref = self._get_ref_by_node_id(session, parsed.node_id)
        if folder_ref is None or not folder_ref.is_folder:
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.FAILED,
                message="Folder node not found",
            )

        parent = self._get_parent_ref(session, parsed.new_parent_node_id)
        folder_ref.parent = parent
        folder_ref.name = parsed.new_name
        session.flush()
        self._upsert_sync_state(
            session=session,
            node_id=parsed.node_id,
            hlc=event.hlc,
            structural=True,
            content=False,
            event_id=event.event_id,
        )
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SUCCESS,
            message="Folder moved",
            affected_ids=[folder_ref.id],
        )

    def _handle_folder_delete(self, session: Session, event: VaultEvent) -> ProcessingResult:
        parsed = FolderDeleteData.from_dict(event.payload)
        if self._is_stale_event(
            event.hlc,
            self._structural_hlc_for_node(session, parsed.node_id),
        ):
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_DUPLICATE,
                message="Stale folder_delete event",
            )
        if self._is_deleted_after_or_equal(session, parsed.node_id, event.hlc):
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_DUPLICATE,
                message="Folder already deleted by a newer event",
            )
        folder_ref = self._get_ref_by_node_id(session, parsed.node_id)
        if folder_ref is None:
            self._record_tombstone(
                session=session,
                node_id=parsed.node_id,
                node_kind="folder",
                event=event,
            )
            self._upsert_sync_state(
                session=session,
                node_id=parsed.node_id,
                hlc=event.hlc,
                structural=True,
                content=False,
                event_id=event.event_id,
            )
            return ProcessingResult(
                event_id=event.event_id,
                event_type=event.type.value,
                status=ProcessingStatus.SKIPPED_IDEMPOTENT,
                message="Folder already deleted",
            )

        affected_ids = self._delete_folder_subtree(session, folder_ref)
        self._record_tombstone(
            session=session,
            node_id=parsed.node_id,
            node_kind="folder",
            event=event,
        )
        self._upsert_sync_state(
            session=session,
            node_id=parsed.node_id,
            hlc=event.hlc,
            structural=True,
            content=False,
            event_id=event.event_id,
        )
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SUCCESS,
            message="Folder deleted",
            affected_ids=affected_ids,
        )

    def _handle_db_dump_created(self, session: Session, event: VaultEvent) -> ProcessingResult:
        del session
        return ProcessingResult(
            event_id=event.event_id,
            event_type=event.type.value,
            status=ProcessingStatus.SUCCESS,
            message="DB dump event recorded",
        )

    @staticmethod
    def _get_ref_by_node_id(session: Session, node_id: str) -> FileReference | None:
        return session.scalar(
            select(FileReference).where(FileReference.node_id == node_id)
        )

    def _get_parent_ref(self, session: Session, parent_node_id: str | None) -> FileReference | None:
        if parent_node_id is None:
            return None
        parent = self._get_ref_by_node_id(session, parent_node_id)
        if parent is None:
            raise ValueError(f"Parent node not found: {parent_node_id}")
        return parent

    def _resolve_parent_for_add(
        self,
        session: Session,
        parent_node_id: str | None,
        event_hlc: HybridLogicalClock,
    ) -> FileReference | None:
        if parent_node_id is None:
            return None
        parent = self._get_ref_by_node_id(session, parent_node_id)
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
                return self._get_or_create_conflict_folder(session)
        raise ValueError(f"Parent node not found: {parent_node_id}")

    def _record_processed_event(
        self,
        *,
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

    def _structural_hlc_for_node(self, session: Session, node_id: str) -> _HLCFields | None:
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
        return _HLCFields(
            wall_time=state.last_structural_hlc_wall_time,
            logical=state.last_structural_hlc_logical,
            device_id=state.last_structural_hlc_device_id,
        )

    def _content_hlc_for_node(self, session: Session, node_id: str) -> _HLCFields | None:
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
        return _HLCFields(
            wall_time=state.last_content_hlc_wall_time,
            logical=state.last_content_hlc_logical,
            device_id=state.last_content_hlc_device_id,
        )

    def _is_stale_event(
        self,
        incoming_hlc: HybridLogicalClock,
        current_hlc: _HLCFields | None,
    ) -> bool:
        if current_hlc is None:
            return False
        return compare_hlc(
            incoming_hlc.to_dict(),
            {
                "wall_time": current_hlc.wall_time,
                "logical": current_hlc.logical,
                "device_id": current_hlc.device_id,
            },
        ) <= 0

    def _is_deleted_after_or_equal(
        self,
        session: Session,
        node_id: str,
        incoming_hlc: HybridLogicalClock,
    ) -> bool:
        tombstone = session.scalar(
            select(SyncTombstone).where(SyncTombstone.node_id == node_id)
        )
        if tombstone is None:
            return False
        return compare_hlc(
            incoming_hlc.to_dict(),
            {
                "wall_time": tombstone.hlc_wall_time,
                "logical": tombstone.hlc_logical,
                "device_id": tombstone.hlc_device_id,
            },
        ) <= 0

    def _upsert_sync_state(
        self,
        *,
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

    def _record_tombstone(
        self,
        *,
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
        if existing.event_id is not None and compare_hlc(event.hlc.to_dict(), current_hlc) <= 0:
            return

        existing.node_kind = node_kind
        existing.event_id = event.event_id
        existing.device_id = event.device_id
        existing.hlc_wall_time = event.hlc.wall_time
        existing.hlc_logical = event.hlc.logical
        existing.hlc_device_id = event.hlc.device_id
        session.flush()

    @staticmethod
    def _delete_folder_subtree(session: Session, folder_ref: FileReference) -> list[int]:
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

    def _get_or_create_conflict_folder(self, session: Session) -> FileReference:
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

    @staticmethod
    def _conflict_name(name: str, hlc: HybridLogicalClock) -> str:
        return f"{name}.conflict.{hlc.wall_time}.{hlc.logical}.{hlc.device_id}"
