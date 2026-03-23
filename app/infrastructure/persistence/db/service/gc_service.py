from pathlib import Path

from sqlalchemy import bindparam, delete, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.infrastructure.persistence.db.model.file_blob_reference import (
    FileBlobReference,
)
from app.infrastructure.persistence.db.model.file_entry import FileEntry
from app.infrastructure.persistence.db.service.session import session_scope
from app.common.paths.vault_layout import writable_blobs_dir
from app.common.logging import logger


class GarbageCollector:
    """Cleans up orphaned FileEntries and their associated blob files."""

    def __init__(self, session_factory: sessionmaker, vault_path: Path):
        self._session_factory = session_factory
        self.vault_file_path = writable_blobs_dir(vault_path)

    def cleanup_orphaned_entry(self, entry_id: int) -> bool:
        """
        Clean up a single orphaned FileEntry.

        Called after a file update switches to a new FileEntry.
        Only deletes if the entry has no remaining references.

        Args:
            entry_id: FileEntry.id to potentially clean up

        Returns:
            True if deleted, False if still referenced
        """
        from app.infrastructure.persistence.db.model.file_reference import FileReference

        with session_scope(self._session_factory) as session:
            # Check if still referenced
            ref_count = session.scalar(
                select(func.count())
                .select_from(FileReference)
                .where(FileReference.file_entry_id == entry_id)
            )

            if ref_count and ref_count > 0:
                logger.debug(
                    f"FileEntry {entry_id} still has {
                        ref_count
                    } reference(s), skipping garbage collection"
                )
                return False

            self._cleanup_batch_in_session(session, [entry_id])
            return True

    def cleanup_batch(self, orphan_ids: list[int]) -> int:
        """Cleans up a batch of orphaned entries in a single pass."""
        if not orphan_ids:
            return 0

        with session_scope(self._session_factory) as session:
            return self._cleanup_batch_in_session(session, orphan_ids)

    def _cleanup_batch_in_session(self, session: Session, orphan_ids: list[int]) -> int:
        """Internal batch cleanup using an existing session."""
        from app.infrastructure.persistence.db.model.file_reference import FileReference

        logger.debug(f"Cleaning up batch of {len(orphan_ids)} orphaned entries")
        if not orphan_ids:
            return 0

        orphan_ids = sorted(set(orphan_ids))
        live_entry_ids = set(
            session.scalars(
                select(FileReference.file_entry_id).where(
                    FileReference.file_entry_id.in_(orphan_ids)
                )
            ).all()
        )
        removable_ids = [
            entry_id for entry_id in orphan_ids if entry_id not in live_entry_ids
        ]
        skipped_ids = [
            entry_id for entry_id in orphan_ids if entry_id in live_entry_ids
        ]

        if skipped_ids:
            logger.debug(
                f"Skipping cleanup for still-referenced file entries: {skipped_ids}"
            )
        if not removable_ids:
            return 0

        # Collect all blob IDs for these entries
        blobs_to_delete = (
            session.execute(
                select(FileBlobReference.blob_id).where(
                    FileBlobReference.file_entry_id.in_(removable_ids)
                )
            )
            .scalars()
            .all()
        )
        blob_ids = list(blobs_to_delete)
        logger.debug(f"Found {len(blob_ids)} blob references to delete")

        # Delete Blob References
        session.execute(
            delete(FileBlobReference).where(
                FileBlobReference.file_entry_id.in_(removable_ids)
            )
        )
        logger.debug(f"Deleted blob references for {len(removable_ids)} entries")

        # Delete Search Index (FTS5)
        try:
            # Use SQLAlchemy expanding bindparam to pass a list/tuple into an IN clause
            session.execute(
                text("DELETE FROM search_index WHERE file_entry_id IN :ids").bindparams(
                    bindparam("ids", expanding=True)
                ),
                {"ids": removable_ids},
            )
            logger.debug(
                f"Deleted search index entries for {len(removable_ids)} entries"
            )
        except Exception as e:
            # FTS5 table may not exist
            logger.debug(f"Skipping search_index cleanup: {e}")

        # 3. Delete FileEntries
        session.execute(delete(FileEntry).where(FileEntry.id.in_(removable_ids)))
        logger.debug(f"Deleted {len(removable_ids)} file entries from database")

        session.flush()

        # 4. Cleanup Disk
        deleted_count = 0
        for blob_id in blob_ids:
            blob_path = self.vault_file_path / blob_id
            try:
                blob_path.unlink(missing_ok=True)
                deleted_count += 1
            except Exception as e:
                logger.error(f"Failed to delete disk file {blob_id}: {e}")

        logger.info(
            f"""Batch cleanup complete: {len(removable_ids)} entries.
            {deleted_count}/{len(blob_ids)} blobs removed from disk"""
        )
        return len(removable_ids)

    def full_gc_sweep(self) -> int:
        """Perform a full garbage collection sweep."""
        logger.info("Starting full GC sweep")

        with session_scope(self._session_factory) as session:
            stmt = text("""
                SELECT fe.id FROM file_entry fe
                WHERE NOT EXISTS (
                    SELECT 1 FROM file_reference fr
                    WHERE fr.file_entry_id = fe.id
                )
            """)

            orphan_ids = [row[0] for row in session.execute(stmt)]

            if not orphan_ids:
                logger.info("No orphaned entries found, skipping GC")
                return 0

            logger.info(f"Found {len(orphan_ids)} orphaned entries to clean up")

            # Process in chunks of 100 to avoid locking the DB for too long
            total_cleaned = 0
            chunk_size = 100
            for i in range(0, len(orphan_ids), chunk_size):
                batch = orphan_ids[i : i + chunk_size]
                total_cleaned += self._cleanup_batch_in_session(session, batch)

            logger.info(f"GC sweep complete: {total_cleaned} entries cleaned")
            return total_cleaned
