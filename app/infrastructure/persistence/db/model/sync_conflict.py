from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.persistence.db.base_model import Base


SYNC_CONFLICT_STATUSES = ("active", "resolved", "deleted")


class SyncConflict(Base):
    """Replayable projection of shared sync-conflict metadata."""

    __tablename__ = "sync_conflict"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'resolved', 'deleted')",
            name="ck_sync_conflict_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    conflict_id: Mapped[str] = mapped_column(
        String, nullable=False, unique=True, index=True
    )
    node_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    node_kind: Mapped[str] = mapped_column(String, nullable=False)

    archived_file_ref_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("file_reference.id", ondelete="SET NULL"),
        nullable=True,
    )
    file_entry_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("file_entry.id", ondelete="SET NULL"),
        nullable=True,
    )
    archived_name: Mapped[str] = mapped_column(String, nullable=False)
    archived_virtual_path: Mapped[str | None] = mapped_column(Text, nullable=True)

    reason_code: Mapped[str] = mapped_column(String, nullable=False)
    reason_text: Mapped[str] = mapped_column(Text, nullable=False)
    trigger_event_id: Mapped[str] = mapped_column(String, nullable=False)
    trigger_event_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    trigger_event_type: Mapped[str] = mapped_column(String, nullable=False)
    origin_device_id: Mapped[str] = mapped_column(String, nullable=False)

    status: Mapped[str] = mapped_column(
        String, nullable=False, default="active", index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolution_event_id: Mapped[str | None] = mapped_column(String, nullable=True)
