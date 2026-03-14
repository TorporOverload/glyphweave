"""File service for managing FileEntry, FileBlobReference, and FileReference
records."""

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import joinedload, sessionmaker

from app.core.database.model.file_blob_reference import FileBlobReference
from app.core.database.model.file_entry import FileEntry
from app.core.database.model.file_reference import FileReference
from app.core.database.service.session import session_scope
from app.utils.logging import logger


class FileService:
    def __init__(self, session_factory: sessionmaker) -> None:
        self._session_factory = session_factory

    def get_file_entry_by_file_id(self, file_id: str) -> Optional[FileEntry]:
        """
        **For files only! not for folders**

        get a FileEntry by its file_id (UUID string).

        Args:
            file_id: The file_id
        Returns:
            FileEntry or None
        """
        with session_scope(self._session_factory, commit=False) as session:
            return (
                session.query(FileEntry)
                .options(joinedload(FileEntry.blobs))
                .filter_by(file_id=file_id)
                .first()
            )

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
        with session_scope(self._session_factory, commit=False) as session:
            return session.query(FileEntry).filter_by(content_hash=content_hash).first()

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
        with session_scope(self._session_factory) as session:
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
            session.add(entry)
            session.flush()  # Get the ID

            # Create blob references
            for idx, blob_id in enumerate(blob_ids):
                blob_ref = FileBlobReference(
                    file_entry_id=entry.id,
                    blob_id=blob_id,
                    blob_index=idx,
                )
                session.add(blob_ref)

            session.flush()

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
        with session_scope(self._session_factory, commit=False) as session:
            return (
                session.query(FileReference)
                .options(
                    joinedload(FileReference.file_entry).joinedload(FileEntry.blobs)
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
        with session_scope(self._session_factory) as session:
            ref = session.get(FileReference, ref_id)
            if not ref:
                return None

            old_entry_id = ref.file_entry_id
            ref.file_entry_id = new_file_entry_id
            ref.modified_at = datetime.now(timezone.utc)
            session.flush()

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
            The created FileReference (is_folder=False) with file_entry
            eagerly loaded via joinedload.
        """
        with session_scope(self._session_factory) as session:
            parent_ref = None
            if parent_id is not None:
                parent_ref = session.get(FileReference, parent_id)
                if parent_ref is None:
                    raise FileNotFoundError(f"Parent folder {parent_id} not found")
                if not parent_ref.is_folder:
                    raise NotADirectoryError(
                        f"Parent reference {parent_id} is not a folder"
                    )

            ref = FileReference(
                name=name,
                parent=parent_ref,
                is_folder=False,
                file_entry_id=file_entry_id,
            )
            session.add(ref)
            session.flush()

            result = (
                session.query(FileReference)
                .options(
                    joinedload(FileReference.file_entry).joinedload(FileEntry.blobs)
                )
                .filter(FileReference.id == ref.id)
                .first()
            )

            if result is None:
                raise RuntimeError(
                    "Unexpected: created FileReference could not be re-fetched "
                    f"(id={ref.id})"
                )

            logger.debug(f"Created file ref: {result.virtual_path} (id={result.id})")
            return result

    def create_empty_file(self, name: str, parent_id: Optional[int]) -> FileReference:
        """
        Creates a new, empty file in the vault.
        - Creates a FileEntry with zero size and a new file_id.
        - Creates a FileReference pointing to it.

        The returned FileReference has ``file_entry`` eagerly loaded via
        ``joinedload`` so it can safely be used after the session closes.
        """
        import hashlib
        import secrets

        with session_scope(self._session_factory) as session:
            time_now = datetime.now(timezone.utc)
            file_id = secrets.token_hex(16)

            parent_ref = None
            if parent_id is not None:
                parent_ref = session.get(FileReference, parent_id)
                if parent_ref is None:
                    raise FileNotFoundError(f"Parent folder {parent_id} not found")
                if not parent_ref.is_folder:
                    raise NotADirectoryError(
                        f"Parent reference {parent_id} is not a folder"
                    )

            # Create an empty FileEntry
            # content_hash is NOT NULL + UNIQUE, so use sha256(file_id) as a
            # unique sentinel for empty files.
            empty_entry = FileEntry(
                file_id=file_id,
                content_hash=hashlib.sha256(file_id.encode()).hexdigest(),
                mime_type="application/octet-stream",
                encrypted_size_bytes=0,
                original_size_bytes=0,
                created_at=time_now,
                updated_at=time_now,
            )
            session.add(empty_entry)
            session.flush()

            # Create a FileReference pointing to the empty entry
            file_ref = FileReference(
                name=name,
                parent=parent_ref,
                is_folder=False,
                file_entry_id=empty_entry.id,
            )
            session.add(file_ref)
            session.flush()

            # Re-query with joinedload to properly populate file_entry
            result = (
                session.query(FileReference)
                .options(
                    joinedload(FileReference.file_entry).joinedload(FileEntry.blobs)
                )
                .filter(FileReference.id == file_ref.id)
                .first()
            )

            if result is None:
                raise RuntimeError(
                    "Unexpected: created empty FileReference could not be re-fetched "
                    f"(id={file_ref.id})"
                )

            logger.info(
                f"Created new empty file '{name}' (ref_id={result.id}, entry_id={
                    empty_entry.id
                })"
            )
            return result
