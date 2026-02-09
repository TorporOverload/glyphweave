from pathlib import Path

from sqlalchemy import delete, text
from sqlalchemy.orm import Session

from app.core.database.model.file_blob_reference import FileBlobReference
from app.core.database.model.file_entry import FileEntry
from app.utils.logging import logger


class GarbageCollector:
    """Cleans up orphaned FileEntries and their associated blob files."""

    def __init__(self, db_session: Session, vault_path: Path):
        self.db = db_session
        self.vault_file_path = vault_path / "files"

    def cleanup_batch(self, orphan_ids: list[int]) -> int:
        """Cleans up a batch of orphaned entries in a single pass."""
        if not orphan_ids:
            return 0

        logger.debug(f"Cleaning up batch of {len(orphan_ids)} orphaned entries")

        # 1. Collect all blob IDs for these entries in one query
        # This assumes a relationship exists on FileEntry.blobs
        blobs_to_delete = (
            self.db.query(FileBlobReference.blob_id)
            .filter(FileBlobReference.file_entry_id.in_(orphan_ids))
            .all()
        )
        blob_ids = [b[0] for b in blobs_to_delete]
        logger.debug(f"Found {len(blob_ids)} blob references to delete")

        # 2. Bulk delete related records

        # A. Delete Blob References
        self.db.execute(
            delete(FileBlobReference).where(
                FileBlobReference.file_entry_id.in_(orphan_ids)
            )
        )
        logger.debug(f"Deleted blob references for {len(orphan_ids)} entries")

        # B. Delete Search Index (FTS5)
        self.db.execute(
            text("DELETE FROM search_index WHERE file_entry_id IN :ids"),
            {"ids": tuple(orphan_ids)},
        )
        logger.debug(f"Deleted search index entries for {len(orphan_ids)} entries")

        # 3. Delete FileEntries
        self.db.execute(delete(FileEntry).where(FileEntry.id.in_(orphan_ids)))
        logger.debug(f"Deleted {len(orphan_ids)} file entries from database")

        self.db.commit()

        # 4. Cleanup Disk (OS operations are the bottleneck)
        deleted_count = 0
        for blob_id in blob_ids:
            blob_path = self.vault_file_path / blob_id
            try:
                blob_path.unlink(missing_ok=True)
                deleted_count += 1
            except Exception as e:
                logger.error(f"Failed to delete disk file {blob_id}: {e}")

        logger.info(
            f"""Batch cleanup complete: {len(orphan_ids)} entries.
            {deleted_count}/{len(blob_ids)} blobs removed from disk"""
        )
        return len(orphan_ids)

    def full_gc_sweep(self) -> int:
        """Perform a full garbage collection sweep."""
        logger.info("Starting full GC sweep")

        stmt = text("""
            SELECT fe.id FROM file_entry fe
            WHERE NOT EXISTS (
                SELECT 1 FROM file_reference fr
                WHERE fr.file_entry_id = fe.id
            )
        """)

        orphan_ids = [row[0] for row in self.db.execute(stmt)]

        if not orphan_ids:
            logger.info("No orphaned entries found, skipping GC")
            return 0

        logger.info(f"Found {len(orphan_ids)} orphaned entries to clean up")

        # Process in chunks of 100 to avoid locking the DB for too long
        total_cleaned = 0
        chunk_size = 100
        for i in range(0, len(orphan_ids), chunk_size):
            batch = orphan_ids[i : i + chunk_size]
            total_cleaned += self.cleanup_batch(batch)

        logger.info(f"GC sweep complete: {total_cleaned} entries cleaned")
        return total_cleaned
