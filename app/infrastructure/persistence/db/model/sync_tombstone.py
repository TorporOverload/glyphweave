from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.persistence.db.base_model import Base


class SyncTombstone(Base):
    """Delete marker retained for sync conflict resolution after row removal."""

    __tablename__ = "sync_tombstone"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[str] = mapped_column(
        String, nullable=False, unique=True, index=True
    )
    node_kind: Mapped[str] = mapped_column(String, nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    hlc_wall_time: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    hlc_logical: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hlc_device_id: Mapped[str] = mapped_column(String, nullable=False)
    deleted_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )
