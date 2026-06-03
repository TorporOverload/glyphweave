from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.infrastructure.persistence.db.model.sync_conflict import SyncConflict


def upsert_sync_conflict(
    session: Session,
    *,
    conflict_id: str,
    node_id: str,
    node_kind: str,
    archived_name: str,
    archived_virtual_path: str | None,
    archived_file_ref_id: int | None,
    file_entry_id: int | None,
    reason_code: str,
    reason_text: str,
    trigger_event_id: str,
    trigger_event_hash: str | None,
    trigger_event_type: str,
    origin_device_id: str,
    status: str = "active",
) -> SyncConflict:
    """Insert or update a sync conflict record.

    When a record with the same ``conflict_id`` already exists, all mutable
    fields are overwritten.  This is intentional for replay idempotency:
    replaying the same event produces the same deterministic ``conflict_id``
    (via ``uuid5``) and identical field values, so the overwrite is a no-op in
    practice.
    """
    conflict = session.scalar(
        select(SyncConflict).where(SyncConflict.conflict_id == conflict_id)
    )
    if conflict is None:
        conflict = SyncConflict(
            conflict_id=conflict_id,
            node_id=node_id,
            node_kind=node_kind,
            archived_name=archived_name,
            archived_virtual_path=archived_virtual_path,
            archived_file_ref_id=archived_file_ref_id,
            file_entry_id=file_entry_id,
            reason_code=reason_code,
            reason_text=reason_text,
            trigger_event_id=trigger_event_id,
            trigger_event_hash=trigger_event_hash,
            trigger_event_type=trigger_event_type,
            origin_device_id=origin_device_id,
            status=status,
        )
        session.add(conflict)
        session.flush()
        return conflict

    conflict.node_id = node_id
    conflict.node_kind = node_kind
    conflict.archived_name = archived_name
    conflict.archived_virtual_path = archived_virtual_path
    conflict.archived_file_ref_id = archived_file_ref_id
    conflict.file_entry_id = file_entry_id
    conflict.reason_code = reason_code
    conflict.reason_text = reason_text
    conflict.trigger_event_id = trigger_event_id
    conflict.trigger_event_hash = trigger_event_hash
    conflict.trigger_event_type = trigger_event_type
    conflict.origin_device_id = origin_device_id
    conflict.status = status
    session.flush()
    return conflict


def get_active_sync_conflict_for_node(
    session: Session, node_id: str
) -> SyncConflict | None:
    return session.scalar(
        select(SyncConflict)
        .where(SyncConflict.node_id == node_id, SyncConflict.status == "active")
        .order_by(SyncConflict.created_at.desc())
    )


def get_sync_conflict_by_id(
    session: Session, conflict_id: str
) -> SyncConflict | None:
    return session.scalar(
        select(SyncConflict).where(SyncConflict.conflict_id == conflict_id)
    )


def list_active_sync_conflicts(session: Session) -> list[SyncConflict]:
    return list(
        session.scalars(
            select(SyncConflict)
            .where(SyncConflict.status == "active")
            .order_by(SyncConflict.created_at.desc())
        ).all()
    )


def list_all_sync_conflicts(session: Session) -> list[SyncConflict]:
    """Return every conflict regardless of status, newest first.

    Used by the GUI's conflict dialog to populate the historical view when no active conflicts remain.
    """
    return list(
        session.scalars(
            select(SyncConflict).order_by(SyncConflict.created_at.desc())
        ).all()
    )


def list_active_sync_conflicts_for_node_ids(
    session: Session,
    node_ids: Iterable[str],
) -> list[SyncConflict]:
    normalized_node_ids = sorted({str(node_id) for node_id in node_ids if node_id})
    if not normalized_node_ids:
        return []

    return list(
        session.scalars(
            select(SyncConflict)
            .where(
                SyncConflict.status == "active",
                SyncConflict.node_id.in_(normalized_node_ids),
            )
            .order_by(SyncConflict.created_at.desc(), SyncConflict.conflict_id.desc())
        ).all()
    )


def resolve_sync_conflict(
    session: Session,
    *,
    conflict_id: str,
    resolution_event_id: str,
    status: str = "deleted",
) -> SyncConflict | None:
    conflict = session.scalar(
        select(SyncConflict).where(SyncConflict.conflict_id == conflict_id)
    )
    if conflict is None:
        return None

    if conflict.status != "active":
        return conflict  # already resolved - no-op for idempotent replay

    conflict.status = status
    conflict.resolution_event_id = resolution_event_id
    conflict.resolved_at = datetime.now(timezone.utc)
    session.flush()
    return conflict


def resolve_active_sync_conflicts_for_node_ids(
    session: Session,
    *,
    node_ids: Iterable[str],
    resolution_event_id: str,
    status: str = "deleted",
) -> list[SyncConflict]:
    conflicts = list_active_sync_conflicts_for_node_ids(session, node_ids)
    if not conflicts:
        return []

    resolved_at = datetime.now(timezone.utc)
    for conflict in conflicts:
        conflict.status = status
        conflict.resolution_event_id = resolution_event_id
        conflict.resolved_at = resolved_at
    session.flush()
    return conflicts
