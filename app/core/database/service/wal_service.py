from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from sqlalchemy.orm import Session, sessionmaker

from app.core.database.model.WAL_entry import WalEntry
from app.core.fuse.temp_store import TempStore
from app.utils.logging import logger


class WalService:
    """
    Database-backed Write-Ahead Log service.

    Provides durability for uncommitted writes by:
    1. Writing chunk data to encrypted temp blobs
    2. Recording the write in the WalEntry table
    3. Supporting recovery on crash by replaying unflushed entries

    Usage:
        wal_service = WalService(session_factory, temp_store)

        # Log a write
        entry = wal_service.log_write(
            file_ref_id=42,
            chunk_index=5,
            offset=327680,
            length=65536,
            data=chunk_bytes,
            file_id="abc123...",
        )

        # After flush succeeds
        wal_service.mark_flushed([entry.id])

        # Periodic cleanup
        wal_service.checkpoint(file_ref_id=42)
    """

    def __init__(
        self,
        session_factory: sessionmaker,
        temp_store: TempStore,
    ):
        """
        Initialize the WAL service.

        Args:
            session_factory: SQLAlchemy session factory for database operations
            temp_store: For managing encrypted temp blob files
        """
        self._session_factory = session_factory
        self.temp_store = temp_store

    @contextmanager
    def _session_scope(self, *, commit: bool = True):
        """Provide a transactional scope around a series of operations."""
        session: Session = self._session_factory()
        session.expire_on_commit = False
        try:
            yield session
            if commit:
                session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def log_write(
        self,
        file_ref_id: int,
        chunk_index: int,
        offset: int,
        length: int,
        data: bytes,
        file_id: str,
    ) -> WalEntry:
        """
        Log a chunk write operation to the WAL.

        Creates a WalEntry record and writes the chunk data to an
        encrypted temp blob. After this method returns, the write
        is durable (will survive a crash).

        Args:
            file_ref_id: FileReference.id being written to
            chunk_index: Index of the chunk (0-based)
            offset: Byte offset in the file
            length: Length of the data
            data: Plaintext chunk data
            file_id: File ID for encryption key derivation

        Returns:
            The created WalEntry
        """
        # Write encrypted temp blob
        temp_blob_id = self.temp_store.write_temp_blob(
            file_id=file_id,
            chunk_index=chunk_index,
            plaintext=data,
        )

        with self._session_scope() as session:
            # Create WalEntry
            entry = WalEntry(
                file_reference_id=file_ref_id,
                operation="write",
                chunk_index=chunk_index,
                offset=offset,
                length=length,
                file_id=file_id,
                temp_blob_id=temp_blob_id,
                flushed=False,
            )

            session.add(entry)
            session.flush()

            logger.debug(
                f"WAL: logged write for ref={file_ref_id}, "
                f"chunk={chunk_index}, blob={temp_blob_id[:8]}..."
            )

            return entry

    def log_truncate(
        self,
        file_ref_id: int,
        new_size: int,
        file_id: str,
    ) -> WalEntry:
        """
        Log a truncate operation to the WAL.

        Args:
            file_ref_id: FileReference.id being truncated
            new_size: New file size in bytes
            file_id: File ID for context

        Returns:
            The created WalEntry
        """
        with self._session_scope() as session:
            entry = WalEntry(
                file_reference_id=file_ref_id,
                operation="truncate",
                chunk_index=0,
                offset=0,
                length=new_size,  # Store new_size in length field
                file_id=file_id,
                temp_blob_id="",  # No temp blob for truncate
                flushed=False,
            )

            session.add(entry)
            session.flush()

            logger.debug(
                f"WAL: logged truncate for ref={file_ref_id}, new_size={new_size}"
            )

            return entry

    def get_pending_entries(self, file_ref_id: int) -> List[WalEntry]:
        """
        Get all unflushed WAL entries for a file.

        Used during flush to know which chunks need to be written
        to final blob storage.

        Args:
            file_ref_id: FileReference.id to query

        Returns:
            List of unflushed WalEntry records, ordered by id
        """
        with self._session_scope(commit=False) as session:
            return (
                session.query(WalEntry)
                .filter(
                    WalEntry.file_reference_id == file_ref_id,
                    WalEntry.flushed.is_(False),
                )
                .order_by(WalEntry.id)
                .all()
            )

    def get_dirty_chunk_indices(self, file_ref_id: int) -> Set[int]:
        """
        Get set of chunk indices with pending writes.

        for flush operations to know which chunks are dirty.

        Args:
            file_ref_id: FileReference.id to query

        Returns:
            Set of chunk indices with unflushed write entries
        """
        with self._session_scope(commit=False) as session:
            entries = (
                session.query(WalEntry.chunk_index)
                .filter(
                    WalEntry.file_reference_id == file_ref_id,
                    WalEntry.operation == "write",
                    WalEntry.flushed.is_(False),
                )
                .distinct()
                .all()
            )
            return {e[0] for e in entries}

    def mark_flushed(self, entry_ids: List[int]) -> None:
        """
        Mark WAL entries as flushed.

        Called after dirty chunks have been successfully written to
        final blob storage. The entries remain in the database until
        checkpoint() is called.

        Args:
            entry_ids: List of WalEntry.id values to mark
        """
        if not entry_ids:
            return

        with self._session_scope() as session:
            now = datetime.now(timezone.utc)
            (
                session.query(WalEntry)
                .filter(WalEntry.id.in_(entry_ids))
                .update(
                    {"flushed": True, "flushed_at": now},
                    synchronize_session=False,
                )
            )
            session.flush()

            logger.debug(f"WAL: marked {len(entry_ids)} entries as flushed")

    def checkpoint(self, file_ref_id: int) -> int:
        """
        Checkpoint WAL entries for a file.

        Deletes all flushed WalEntry records and their associated
        temp blobs. This should be called after a successful flush
        to clean up WAL state.

        Args:
            file_ref_id: FileReference.id to checkpoint

        Returns:
            Number of entries deleted
        """
        with self._session_scope() as session:
            # Get flushed entries
            entries = (
                session.query(WalEntry)
                .filter(
                    WalEntry.file_reference_id == file_ref_id,
                    WalEntry.flushed,
                )
                .all()
            )

            if not entries:
                return 0

            # Delete temp blobs
            for entry in entries:
                if entry.temp_blob_id:
                    self.temp_store.delete_temp_blob(entry.temp_blob_id)

            # Delete entries
            entry_ids = [e.id for e in entries]
            (
                session.query(WalEntry)
                .filter(WalEntry.id.in_(entry_ids))
                .delete(synchronize_session=False)
            )
            session.flush()

            logger.debug(
                f"WAL: checkpointed {len(entries)} entries for ref={file_ref_id}"
            )
            return len(entries)

    def checkpoint_all_flushed(self) -> int:
        """
        Checkpoint all flushed WAL entries across all files.

        Used during shutdown or periodic cleanup.

        Returns:
            Total number of entries deleted
        """
        with self._session_scope() as session:
            entries = (
                session.query(WalEntry)
                .filter(WalEntry.flushed.is_(True))
                .all()
            )

            if not entries:
                return 0

            # Delete temp blobs
            for entry in entries:
                if entry.temp_blob_id:
                    self.temp_store.delete_temp_blob(entry.temp_blob_id)

            # Delete entries
            entry_ids = [e.id for e in entries]
            (
                session.query(WalEntry)
                .filter(WalEntry.id.in_(entry_ids))
                .delete(synchronize_session=False)
            )
            session.flush()

            logger.info(f"WAL: checkpointed {len(entries)} entries globally")
            return len(entries)

    def get_unflushed_for_recovery(self) -> Dict[int, List[WalEntry]]:
        """
        Get all unflushed WAL entries for crash recovery.

        Groups entries by file_reference_id for per-file recovery.

        Returns:
            Dict mapping file_reference_id to list of unflushed entries
        """
        with self._session_scope(commit=False) as session:
            entries = (
                session.query(WalEntry)
                .filter(WalEntry.flushed.is_(False))
                .order_by(WalEntry.file_reference_id, WalEntry.id)
                .all()
            )

            result: Dict[int, List[WalEntry]] = {}
            for entry in entries:
                if entry.file_reference_id not in result:
                    result[entry.file_reference_id] = []
                result[entry.file_reference_id].append(entry)

            return result

    def read_chunk_from_wal(self, entry: WalEntry) -> Optional[bytes]:
        """
        Read chunk data from a WAL entry's temp blob.

        Used during recovery to reconstruct dirty chunk content.

        Args:
            entry: The WalEntry to read

        Returns:
            Decrypted plaintext chunk data, or None if blob missing
        """
        if not entry.temp_blob_id:
            return None

        return self.temp_store.read_temp_blob(
            file_id=entry.file_id,
            chunk_index=entry.chunk_index,
            blob_id=entry.temp_blob_id,
        )

    def get_latest_chunk_entries(self, file_ref_id: int) -> Dict[int, WalEntry]:
        """
        Get the latest WAL entry for each dirty chunk.

        When multiple writes happen to the same chunk, only the latest
        matters for recovery. This returns a dict mapping chunk_index
        to the most recent WalEntry for that chunk.

        Args:
            file_ref_id: FileReference.id to query

        Returns:
            Dict mapping chunk_index to latest WalEntry
        """
        entries = self.get_pending_entries(file_ref_id)

        latest: Dict[int, WalEntry] = {}
        for entry in entries:
            if entry.operation == "write":
                # Later entry (higher id) overwrites earlier
                latest[entry.chunk_index] = entry

        return latest

    def cleanup_orphaned_blobs(self) -> int:
        """
        Clean up temp blobs not referenced by any WalEntry.

        Called during startup to recover from partial checkpoint
        or other inconsistent states.

        Returns:
            Number of orphaned blobs deleted
        """
        with self._session_scope(commit=False) as session:
            # Get all blob IDs currently in database
            db_blob_ids = {
                row[0]
                for row in session.query(WalEntry.temp_blob_id)
                .filter(WalEntry.temp_blob_id != "")
                .distinct()
                .all()
            }

            return self.temp_store.cleanup_orphaned(db_blob_ids)

    def has_pending_writes(self, file_ref_id: int) -> bool:
        """
        Check if a file has any unflushed WAL entries.

        Args:
            file_ref_id: FileReference.id to check

        Returns:
            True if there are pending writes
        """
        with self._session_scope(commit=False) as session:
            count = (
                session.query(WalEntry)
                .filter(
                    WalEntry.file_reference_id == file_ref_id,
                    WalEntry.flushed.is_(False),
                )
                .count()
            )
            return count > 0

    def count_pending(self) -> int:
        """Get total count of unflushed WAL entries."""
        with self._session_scope(commit=False) as session:
            return (
                session.query(WalEntry)
                .filter(WalEntry.flushed.is_(False))
                .count()
            )
