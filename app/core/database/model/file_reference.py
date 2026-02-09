from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    event,
    func,
    update,
)
from sqlalchemy.orm import Mapped, Relationship, mapped_column, relationship
from sqlalchemy.orm.attributes import get_history

from app.core.database.base import Base

if TYPE_CHECKING:
    from app.core.database.model.file_entry import FileEntry
    from app.core.database.model.WAL_entry import WalEntry


class FileReference(Base):
    """Represents a node in the virtual file tree (file or folder)."""

    __tablename__ = "file_reference"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    parent_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("file_reference.id"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String, nullable=False, index=True)
    is_folder: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Cached full path for fast lookup (e.g. "/docs/report.txt")
    # Kept in sync by events and FolderService on create/rename/move
    virtual_path: Mapped[str] = mapped_column(
        String, nullable=False, index=True, unique=True
    )

    added_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    modified_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    accessed_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    # File-specific
    file_entry_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("file_entry.id"), nullable=True
    )

    # Relationships
    parent: Relationship[Optional["FileReference"]] = relationship(
        "FileReference", remote_side=[id], backref="children"
    )
    file_entry: Relationship[Optional["FileEntry"]] = relationship(
        "FileEntry", back_populates="references"
    )
    wal_entries: Relationship[List["WalEntry"]] = relationship(
        "WalEntry", back_populates="file_reference"
    )

    @property
    def path(self) -> str:
        if self.virtual_path:
            return self.virtual_path

        # fallback for unsaved objects
        parent_path = self.parent.path if self.parent else ""
        return f"{parent_path}/{self.name}"


@event.listens_for(FileReference, "before_insert")
@event.listens_for(FileReference, "before_update")
def generate_virtual_path(_mapper, _connection, target: FileReference) -> None:
    """
    Ensure `virtual_path` is set correctly from parent + name before persisting.
    This keeps the cached path consistent for new/updated rows.
    """
    parent_path = target.parent.virtual_path if target.parent else ""
    target.virtual_path = f"{parent_path}/{target.name}"


@event.listens_for(FileReference, "after_update")
def propagate_path_to_children(mapper, connection, target: FileReference) -> None:
    if not target.is_folder:
        return

    history = get_history(target, "virtual_path")
    if not history.has_changes():
        return

    old_path = history.deleted[0] if history.deleted else None
    new_path = target.virtual_path

    if old_path and new_path:
        stmt = (
            update(FileReference)
            .where(FileReference.virtual_path.like(old_path + "/%"))
            .values(
                virtual_path=new_path
                + func.substr(FileReference.virtual_path, len(old_path) + 1)
            )
        )

        connection.execute(stmt)
