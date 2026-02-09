from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Relationship, relationship, Mapped, mapped_column

if TYPE_CHECKING:
    from app.core.database.model.file_reference import FileReference

from app.core.database.base import Base


class WalEntry(Base):
    """Write-Ahead Log entry for pending writes to blob storage."""

    __tablename__ = "wal_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_reference_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("file_reference.id"), nullable=False
    )
    operation: Mapped[str] = mapped_column(String, nullable=False)
    offset: Mapped[int] = mapped_column(Integer, default=0)
    length: Mapped[int] = mapped_column(Integer, nullable=False)
    temp_blob_id: Mapped[str] = mapped_column(String, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    flushed: Mapped[bool] = mapped_column(Boolean, default=False)
    flushed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    file_reference: Relationship["FileReference"] = relationship(
        "FileReference",
        back_populates="wal_entries",
        foreign_keys=[file_reference_id],
    )
