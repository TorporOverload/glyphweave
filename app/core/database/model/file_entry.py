from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import (
    Mapped,
    Relationship,
    mapped_column,
    relationship,
)

from app.core.database.base import Base

if TYPE_CHECKING:
    from app.core.database.model.file_blob_reference import FileBlobReference
    from app.core.database.model.file_reference import FileReference


class FileEntry(Base):
    __tablename__ = "file_entry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_id: Mapped[str] = mapped_column(String, unique=True, nullable=False)  # UUID
    content_hash: Mapped[str] = mapped_column(
        String, unique=True, nullable=False
    )  # SHA256 for dedup
    mime_type: Mapped[str] = mapped_column(String, nullable=False)
    encrypted_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    original_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    text_extraction_status: Mapped[str] = mapped_column(String, default="pending")
    extracted_text_preview: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    references: Relationship[List["FileReference"]] = relationship(
        "FileReference", back_populates="file_entry"
    )
    blobs: Relationship[List["FileBlobReference"]] = relationship(
        "FileBlobReference",
        back_populates="file_entry",
        order_by="FileBlobReference.blob_index",
    )
