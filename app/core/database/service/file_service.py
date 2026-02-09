"""
File service for managing FileEntry, FileBlobReference, and FileReference records.

Provides both legacy methods (for GUI tree browsing) and new dedup-aware methods
used by the FUSE layer when flushing modified files to blob storage.
"""

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session, joinedload

from app.core.database.model.file_blob_reference import FileBlobReference
from app.core.database.model.file_entry import FileEntry
from app.core.database.model.file_reference import FileReference
from app.utils.logging import logger


class FileService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_root_entries(self) -> List[FileReference]:
        """Get a list of files and folders at the root of the vault."""
        try:
            return (
                self.session.query(FileReference)
                .filter(FileReference.parent_id.is_(None))
                .all()
            )
        except Exception as e:
            logger.error(f"Error getting root file entries: {e}")
            raise

    def get_children(self, parent_id: int) -> List[FileReference]:
        """Get a list of files and folders within a given folder."""
        try:
            return (
                self.session.query(FileReference)
                .filter(FileReference.parent_id == parent_id)
                .all()
            )
        except Exception as e:
            logger.error(f"Error getting children of folder {parent_id}: {e}")
            raise

    def get_file_reference_by_id(self, file_id: int) -> Optional[FileReference]:
        """Get a file reference by id ()."""
        try:
            return (
                self.session.query(FileReference)
                .filter(FileReference.id == file_id)
                .first()
            )
        except Exception as e:
            logger.error(f"Error getting file by ID {file_id}: {e}")
            raise
            
    def get_file_entry_by_file_id(self, file_id: str) -> Optional[FileEntry]:
        """
        **For files only! not for folders**
        
        get a FileEntry by its file_id (UUID string).
        
        Args:
            file_id: The file_id
        Returns:
            FileEntry or None
        """
        return (
            self.session.query(FileEntry)
            .options(joinedload(FileEntry.blobs))
            .filter_by(file_id=file_id)
            .first()
        )

    def get_vault_tree(self) -> Optional[List[FileReference]]:
        """Get the entire vault tree."""
        try:
            return (
                self.session.query(FileReference)
                .options(joinedload(FileReference.file_entry))
                .order_by(FileReference.parent_id.asc().nullsfirst())
                .all()
            )
        except Exception as e:
            logger.error(f"Error getting vault tree: {e}")
            raise

    def find_by_content_hash(self, content_hash: str) -> Optional[FileEntry]:
        """
        Look up a FileEntry by its content hash for deduplication.

        If a matching hash exists, the program can reuse that FileEntry 
        instead of creating a new one.

        Args:
            content_hash: SHA-256 hex digest of the plaintext content

        Returns:
            Existing FileEntry with matching hash, or None
        """
        return (
            self.session.query(FileEntry)
            .filter_by(content_hash=content_hash)
            .first()
        )

    def create_file_entry_with_blobs(
        self,
        file_id: str,
        content_hash: str,
        mime_type: str,
        encrypted_size: int,
        original_size: int,
        blob_ids: List[str],
    ) -> FileEntry:
        """
        Create a FileEntry and its FileBlobReferences atomically.

        Used when encrypting new/modified content to blob storage.

        Args:
            file_id: UUID string for encryption AAD
            content_hash: SHA-256 of plaintext for dedup
            mime_type: MIME type of the file
            encrypted_size: Total encrypted size across all blobs
            original_size: Original plaintext size
            blob_ids: Ordered list of blob filenames (e.g., ["3f9a...f8c3d.enc"])

        Returns:
            The created FileEntry with blobs relationship populated
        """
        time_now = datetime.now(timezone.utc)

        entry = FileEntry(
            file_id=file_id,
            content_hash=content_hash,
            mime_type=mime_type,
            encrypted_size_bytes=encrypted_size,
            original_size_bytes=original_size,
            created_at=time_now,
            updated_at=time_now,
        )
        self.session.add(entry)
        self.session.flush()  # Get the ID

        # Create blob references
        for idx, blob_id in enumerate(blob_ids):
            blob_ref = FileBlobReference(
                file_entry_id=entry.id,
                blob_id=blob_id,
                blob_index=idx,
            )
            self.session.add(blob_ref)

        self.session.flush()

        logger.debug(
            f"Created FileEntry {entry.id} (file_id={file_id}) "
            f"with {len(blob_ids)} blob(s)"
        )
        return entry

    def get_file_reference_with_blobs(self, ref_id: int) -> Optional[FileReference]:
        """
        Used when opening a file via FUSE to get all blob IDs in one query.

        Args:
            ref_id: FileReference.id

        Returns:
            FileReference with file_entry.blobs loaded, or None
        """
        return (
            self.session.query(FileReference)
            .options(
                joinedload(FileReference.file_entry)
                .joinedload(FileEntry.blobs)
            )
            .filter(FileReference.id == ref_id)
            .first()
        )

    def update_file_reference_entry(
        self, ref_id: int, new_file_entry_id: int
    ) -> Optional[int]:
        """
        Point a FileReference to a different FileEntry.

        Used during dedup: when content matches an existing FileEntry,
        we redirect the reference instead of creating a new entry.

        Args:
            ref_id: The FileReference to update
            new_file_entry_id: The FileEntry to point to

        Returns:
            The old file_entry_id (for orphan GC), or None
        """
        ref = self.session.query(FileReference).get(ref_id)
        if not ref:
            return None

        old_entry_id = ref.file_entry_id
        ref.file_entry_id = new_file_entry_id
        ref.modified_at = datetime.now(timezone.utc)
        self.session.flush()

        logger.debug(
            f"Updated FileReference {ref_id}: "
            f"entry {old_entry_id} -> {new_file_entry_id}"
        )
        return old_entry_id

    def create_file_reference(
        self,
        name: str,
        parent_id: Optional[int],
        file_entry_id: int,
    ) -> FileReference:
        """
        Create a new file reference in the vault tree.

        Args:
            name: File name
            parent_id: Parent folder ID (None for root-level)
            file_entry_id: The FileEntry this reference points to

        Returns:
            The created FileReference (is_folder=False)
        """
        ref = FileReference(
            name=name,
            parent_id=parent_id,
            is_folder=False,
            file_entry_id=file_entry_id,
        )
        self.session.add(ref)
        self.session.flush()

        logger.debug(f"Created file ref: {ref.virtual_path} (id={ref.id})")
        return ref
