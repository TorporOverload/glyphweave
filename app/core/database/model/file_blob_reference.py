from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, Relationship, relationship
from sqlalchemy.orm import mapped_column
from typing import TYPE_CHECKING
from app.core.database.base import Base
if TYPE_CHECKING:
    from app.core.database.model.file_entry import FileEntry


class FileBlobReference(Base):
    """Reference to a stored blob chunk belonging to a FileEntry."""

    __tablename__ = "file_blob_reference"
    __table_args__ = (
        UniqueConstraint("file_entry_id", "blob_index", name="uq_file_blob_index"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_entry_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("file_entry.id"), nullable=False
    )
    blob_id: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    blob_index: Mapped[int] = mapped_column(Integer, nullable=False)

    # Relationship to the owning FileEntry
    file_entry: Relationship["FileEntry"] = relationship(
        "FileEntry", back_populates="blobs"
    )
