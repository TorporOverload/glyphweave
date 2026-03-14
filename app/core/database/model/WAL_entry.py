from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, Relationship, mapped_column, relationship

if TYPE_CHECKING:
    from app.core.database.model.file_reference import FileReference

from app.core.database.base import Base


class WalEntry(Base):
    """Write-Ahead Log entry for pending writes to blob storage.

    Each entry represents a chunk write that hasn't been flushed to
    final blob storage. The chunk data is stored in an encrypted temp
    blob file (referenced by temp_blob_id), not inline in the database.

    Lifecycle:
        1. Created on write with flushed=False
        2. Temp blob written to
                    GLYPHWEAVE_LOCAL_DIR / {vault_id} / cache / temp-blobs /
                    {temp_blob_id}.enc
        3. On flush: chunk written to final blob, flushed=True
        4. On checkpoint: entry deleted, temp blob deleted
    """

    __tablename__ = "wal_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_reference_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("file_reference.id"), nullable=False, index=True
    )

    # Operation type: "write", "truncate"
    operation: Mapped[str] = mapped_column(String, nullable=False)

    # Chunk identification
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)

    # Byte offset within file (chunk_index * chunk_size for aligned writes)
    offset: Mapped[int] = mapped_column(Integer, default=0)

    # Length of plaintext data
    length: Mapped[int] = mapped_column(Integer, nullable=False)

    # File ID for encryption key derivation (from FileEntry.file_id)
    file_id: Mapped[str] = mapped_column(String, nullable=False)

    # Reference to encrypted temp blob:
    # GLYPHWEAVE_LOCAL_DIR / {vault_id} / cache / temp-blobs / {temp_blob_id}.enc
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
