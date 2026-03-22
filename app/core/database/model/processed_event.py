from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database.base_model import Base


class ProcessedEvent(Base):
    """Record of an event seen and processed by the local vault."""

    __tablename__ = "processed_event"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(
        String, nullable=False, unique=True, index=True
    )
    event_hash: Mapped[str] = mapped_column(
        String, nullable=False, unique=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String, nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    hlc_wall_time: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    hlc_logical: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hlc_device_id: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, index=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )
