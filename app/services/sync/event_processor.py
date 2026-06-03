from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

if TYPE_CHECKING:
    from collections.abc import Callable

from app.common.logging import logger
from app.core.domain.sync.hashing import hash_event
from app.core.domain.sync.models import (
    BatchProcessingResult,
    DiscoveredEvent,
    ProcessingResult,
    ProcessingStatus,
    VaultEvent,
)
from app.infrastructure.persistence.db.model.processed_event import ProcessedEvent
from app.infrastructure.persistence.db.service.session import session_scope

from . import file_handlers, file_lifecycle_handlers, folder_handlers, state


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
                try:
                    result = handler(session, event)
                except Exception:
                    session.rollback()
                    logger.error(
                        "Failed to process event %s (%s)",
                        event.event_id,
                        event.type.value,
                        exc_info=True,
                    )
                    result = ProcessingResult(
                        event_id=event.event_id,
                        event_type=event.type.value,
                        status=ProcessingStatus.FAILED,
                        message="Event handler failed",
                    )

            if result.status != ProcessingStatus.FAILED:
                self.record_processed_event(session, event, event_hash, result)
            return result

    def process_discovered_event(self, discovered: DiscoveredEvent) -> ProcessingResult:
        return self.process_event(discovered.event)

    def process_batch(
        self,
        events: list[DiscoveredEvent],
        *,
        progress_callback: "Callable[[int, int], None] | None" = None,
    ) -> BatchProcessingResult:
        """Apply ``events`` in order.

        ``progress_callback`` is invoked with ``(current, total)`` *after*
        each event has been processed, where ``current`` is the 1-based
        index of the event that just finished. So a UI reading the values
        shows "finished N of M", not "about to start N of M".
        """
        results: list[ProcessingResult] = []
        total = len(events)
        for i, event in enumerate(events):
            results.append(self.process_discovered_event(event))
            if progress_callback is not None:
                progress_callback(i + 1, total)
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
        failed = sum(
            1 for result in results if result.status == ProcessingStatus.FAILED
        )
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

    def _handle_file_add(self, session, event):
        return file_handlers.handle_file_add(self, session, event)

    def _handle_file_update(self, session, event):
        return file_handlers.handle_file_update(self, session, event)

    def _handle_file_conflict_archive(self, session, event):
        return file_handlers.handle_file_conflict_archive(self, session, event)

    def _handle_file_conflict_resolved(self, session, event):
        return file_handlers.handle_file_conflict_resolved(self, session, event)

    def _handle_file_move(self, session, event):
        return file_lifecycle_handlers.handle_file_move(self, session, event)

    def _handle_file_delete(self, session, event):
        return file_lifecycle_handlers.handle_file_delete(self, session, event)

    def _handle_folder_create(self, session, event):
        return folder_handlers.handle_folder_create(self, session, event)

    def _handle_folder_conflict_archive(self, session, event):
        return folder_handlers.handle_folder_conflict_archive(self, session, event)

    def _handle_folder_conflict_resolved(self, session, event):
        return folder_handlers.handle_folder_conflict_resolved(self, session, event)

    def _handle_folder_move(self, session, event):
        return folder_handlers.handle_folder_move(self, session, event)

    def _handle_folder_delete(self, session, event):
        return folder_handlers.handle_folder_delete(self, session, event)

    def _handle_db_dump_created(self, session, event):
        return folder_handlers.handle_db_dump_created(self, session, event)

    def get_ref_by_node_id(self, session, node_id):
        return state.get_ref_by_node_id(session, node_id)

    def get_parent_ref(self, session, parent_node_id):
        return state.get_parent_ref(session, parent_node_id)

    def resolve_parent_for_add(self, session, parent_node_id, event_hlc):
        return state.resolve_parent_for_add(self, session, parent_node_id, event_hlc)

    def resolve_parent_for_move(self, session, parent_node_id, event_hlc):
        return state.resolve_parent_for_move(self, session, parent_node_id, event_hlc)

    def record_processed_event(self, session, event, event_hash, result):
        state.record_processed_event(session, event, event_hash, result)

    def structural_hlc_for_node(self, session, node_id):
        return state.structural_hlc_for_node(session, node_id)

    def content_hlc_for_node(self, session, node_id):
        return state.content_hlc_for_node(session, node_id)

    def is_stale_event(self, incoming_hlc, current_hlc):
        return state.is_stale_event(incoming_hlc, current_hlc)

    def is_deleted_after_or_equal(self, session, node_id, incoming_hlc):
        return state.is_deleted_after_or_equal(session, node_id, incoming_hlc)

    def upsert_sync_state(self, session, node_id, hlc, structural, content, event_id):
        state.upsert_sync_state(session, node_id, hlc, structural, content, event_id)

    def record_tombstone(self, session, node_id, node_kind, event):
        state.record_tombstone(session, node_id, node_kind, event)

    def get_or_create_conflict_folder(self, session):
        return folder_handlers.get_or_create_conflict_folder(session)

    def conflict_name(self, name, hlc):
        return folder_handlers.conflict_name(name, hlc)
