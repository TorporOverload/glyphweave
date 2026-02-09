from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from sqlalchemy.orm import Session, joinedload

from app.core.database.model.file_reference import FileReference
from app.core.database.service.gc_service import GarbageCollector
from app.utils.logging import logger


class FolderService:
    """DB operations for the vault folder tree."""

    def __init__(self, session: Session, vault_path: Path):
        self.session = session
        self.vault_path = vault_path
        self.gc = GarbageCollector(session, vault_path)

    def create_folder(
        self,
        name: str,
        parent_id: Optional[int],
    ) -> FileReference:
        """
        Create a new folder in the vault tree.

        Args:
            name: Folder name
            parent_id: Parent folder ID (None for root-level)

        Returns:
            The created FileReference (is_folder=True)
        """
        folder = FileReference(
            name=name,
            parent_id=parent_id,
            is_folder=True,
            file_entry_id=None,
        )
        self.session.add(folder)
        self.session.flush()  # Get the ID without committing

        logger.debug(f"Created folder: {folder.virtual_path} (id={folder.id})")
        return folder

    def get_by_id(self, ref_id: int) -> Optional[FileReference]:
        """Get a FileReference by ID with eager-loaded relationships."""
        return (
            self.session.query(FileReference)
            .options(joinedload(FileReference.file_entry))
            .filter(FileReference.id == ref_id)
            .first()
        )

    def get_by_virtual_path(self, virtual_path: str) -> Optional[FileReference]:
        """Look up a FileReference by its virtual path."""
        return (
            self.session.query(FileReference)
            .filter(FileReference.virtual_path == virtual_path)
            .first()
        )

    def get_folder_id_by_path(self, virtual_path: str) -> Optional[int]:
        """Get the ID of a folder by its virtual path. Returns None if not found."""
        ref = (
            self.session.query(FileReference.id)
            .filter(
                FileReference.virtual_path == virtual_path,
                FileReference.is_folder.is_(True),
            )
            .first()
        )
        return ref[0] if ref else None

    def rename_entry(
        self,
        ref_id: int,
        new_name: str,
        new_parent_id: Optional[int],
    ) -> None:
        """
        Re-name a file entity or a folder

        Args:
            ref_id: The FileReference to rename/move
            new_name: New name
            new_parent_id: New parent folder ID (None for root)
        """
        ref = self.session.query(FileReference).get(ref_id)
        if not ref:
            raise FileNotFoundError(f"FileReference {ref_id} not found")

        ref.name = new_name
        ref.parent_id = new_parent_id

        self.session.flush()
        logger.debug(f"""Renamed FileReference {ref_id} to {new_name} -
            new file path {ref.virtual_path}""")

    def delete_entry(self, ref_id: int, commit: bool = False) -> List[int]:
        """
        Delete a FileReference entry. For folders, recursively deletes
        all children (files and subfolders). Collects file_entry_ids that
        may have become orphaned and returns them for later batch GC.

        Args:
            ref_id: The FileReference to delete
            commit: If True, commit the DB transaction after deletions so
                    subsequent GC runs see the final state.

        Returns:
            A list of potentially orphaned FileEntry IDs that should be
            passed to the garbage collector in a batch.
        """
        ref = self.session.query(FileReference).get(ref_id)
        if not ref:
            return []

        orphaned_entry_ids: set[int] = set()
        virtual_path = ref.virtual_path

        if ref.is_folder:
            # Get all descendants (files and folders) under this folder
            descendants = (
                self.session.query(FileReference)
                .filter(FileReference.virtual_path.like(virtual_path + "/%"))
                .all()
            )

            # Collect file_entry_ids from files and delete descendants
            for desc in descendants:
                if desc.file_entry_id is not None:
                    orphaned_entry_ids.add(desc.file_entry_id)
                self.session.delete(desc)

        # Collect this entry's file_entry_id if it's a file
        if ref.file_entry_id is not None:
            orphaned_entry_ids.add(ref.file_entry_id)

        # Delete the entry itself
        self.session.delete(ref)
        self.session.flush()

        logger.debug(f"Deleted entry: {virtual_path}")

        # Optionally commit deletions so callers can run GC deterministically
        if commit:
            self.session.commit()

        # Return deduplicated list of potentially orphaned FileEntry IDs
        return list(orphaned_entry_ids)


    def update_accessed_at(self, ref_id: int) -> None:
        """Update the accessed_at timestamp for a file reference."""
        ref = self.session.query(FileReference).get(ref_id)
        if ref:
            ref.accessed_at = datetime.now(timezone.utc)
            self.session.flush()
