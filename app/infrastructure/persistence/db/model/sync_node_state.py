from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.persistence.db.base_model import Base


class SyncNodeState(Base):
    """Persisted sync metadata for one logical file/folder node."""

    __tablename__ = "sync_node_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[str] = mapped_column(
        String, nullable=False, unique=True, index=True
    )

    last_structural_hlc_wall_time: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    last_structural_hlc_logical: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    last_structural_hlc_device_id: Mapped[str | None] = mapped_column(
        String, nullable=True
    )

    last_content_hlc_wall_time: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    last_content_hlc_logical: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_content_hlc_device_id: Mapped[str | None] = mapped_column(
        String, nullable=True
    )

    last_event_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

