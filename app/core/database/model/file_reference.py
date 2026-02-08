from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, event
from sqlalchemy.orm import relationship
from sqlalchemy.orm.attributes import get_history

from app.core.database.base import Base


class FileReference(Base):
    __tablename__ = "file_reference"

    id = Column(Integer, primary_key=True)
    parent_id = Column(
        Integer, ForeignKey("file_reference.id"), nullable=True, index=True
    )
    name = Column(String, nullable=False, index=True)
    is_folder = Column(Boolean, nullable=False, default=False)

    # Cached full path for fast lookup (e.g. "/docs/report.txt")
    # Kept in sync by FolderService on create/rename/move
    virtual_path = Column(String, nullable=False, index=True, unique=True)

    added_at = Column(DateTime, default=datetime.now(timezone.utc))
    modified_at = Column(
        DateTime,
        default=datetime.now(timezone.utc),
        onupdate=datetime.now(timezone.utc),
    )
    accessed_at = Column(DateTime, default=datetime.now(timezone.utc))

    # File Specific
    file_entry_id = Column(Integer, ForeignKey("file_entry.id"), nullable=True)

    # Relationships
    parent = relationship("FileReference", remote_side=[id], backref="children")
    file_entry = relationship("FileEntry", back_populates="references")
    wal_entries = relationship("WalEntry", back_populates="file_reference")


@event.listens_for(FileReference, "before_insert")
@event.listens_for(FileReference, "before_update")
def generate_virtual_path(_mapper, _connection, target):
    """Auto-generate virtual_path before saving."""
    parent_path = target.parent.virtual_path if target.parent else ""
    target.virtual_path = f"{parent_path}/{target.name}"


@event.listens_for(FileReference, "after_update")
def propagate_path_to_children(_mapper, _connection, target):
    """When a folder's virtual_path changes, update all children's virtual_path."""
    if not target.is_folder:
        return

    history = get_history(target, "virtual_path")
    if not history.has_changes():
        return

    queue = list(target.children)
    while queue:
        child = queue.pop(0)
        child.virtual_path = f"{child.parent.virtual_path}/{child.name}"
        queue.extend(child.children)
