from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from sqlalchemy import Connection

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    event,
    func,
    literal,
    update,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.orm.attributes import get_history

from app.infrastructure.persistence.db.base_model import Base
from app.infrastructure.persistence.db.utils import escape_like_pattern

if TYPE_CHECKING:
    from app.infrastructure.persistence.db.model.file_entry import FileEntry
    from app.infrastructure.persistence.db.model.WAL_entry import WalEntry


class FileReference(Base):
    """Represents a node in the virtual file tree (file or folder)."""

    __tablename__ = "file_reference"
    __table_args__ = (Index("ix_file_reference_node_id", "node_id", unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[str] = mapped_column(
        String,
        nullable=False,
        default=lambda: str(uuid.uuid4()),
    )
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
    parent: Mapped[Optional["FileReference"]] = relationship(
        "FileReference", remote_side=[id], backref="children"
    )
    file_entry: Mapped[Optional["FileEntry"]] = relationship(
        "FileEntry", back_populates="references"
    )
    wal_entries: Mapped[List["WalEntry"]] = relationship(
        "WalEntry", back_populates="file_reference"
    )

    @property
    def path(self) -> str:
        """Return the virtual path, falling back to a computed path for unsaved
        objects."""
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
def propagate_path_to_children(
    _mapper, connection: Connection, target: FileReference
) -> None:
    """Cascade a folder's virtual path change to all descendant rows."""
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
            .where(
                FileReference.virtual_path.like(
                    escape_like_pattern(old_path) + "/%",
                    escape="\\",
                )
            )
            .values(
                virtual_path=new_path
                + func.substr(
                    FileReference.virtual_path,
                    func.length(literal(old_path)) + 1,
                )
            )
        )

        connection.execute(stmt)
