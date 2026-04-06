from pathlib import Path

from sqlalchemy import bindparam, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.common.logging import logger
from app.common.paths.vault_layout import resolve_blob_path, writable_blobs_dir
from app.infrastructure.persistence.db.model.file_entry import FileEntry
from app.infrastructure.persistence.db.service.session import session_scope


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

            deleted_count, blob_paths = self._cleanup_batch_in_session(
                session, [entry_id]
            )

        self._delete_blob_paths(blob_paths)
        return deleted_count > 0

    def cleanup_batch(self, orphan_ids: list[int]) -> int:
        """Cleans up a batch of orphaned entries in a single pass."""
        if not orphan_ids:
            return 0

        with session_scope(self._session_factory) as session:
            deleted_count, blob_paths = self._cleanup_batch_in_session(
                session, orphan_ids
            )

        self._delete_blob_paths(blob_paths)
        return deleted_count

    def _cleanup_batch_in_session(
        self, session: Session, orphan_ids: list[int]
    ) -> tuple[int, list[Path]]:
        """Internal batch cleanup using an existing session."""
        from app.infrastructure.persistence.db.model.file_reference import FileReference

        logger.debug(f"Cleaning up batch of {len(orphan_ids)} orphaned entries")
        if not orphan_ids:
            return 0, []

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
            return 0, []

        blob_paths: list[Path] = []
        for entry_id in removable_ids:
            entry = session.get(FileEntry, entry_id)
            if entry is None:
                continue
            for blob in entry.blobs:
                blob_path = resolve_blob_path(self.vault_file_path.parent, blob.blob_id)
                if blob_path.exists():
                    blob_paths.append(blob_path)
            session.delete(entry)

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

        session.flush()
        logger.info(
            "Batch cleanup staged: %s entries, %s blob(s) pending disk deletion",
            len(removable_ids),
            len(blob_paths),
        )
        return len(removable_ids), blob_paths

    def full_gc_sweep(self) -> int:
        """Perform a full garbage collection sweep."""
        logger.info("Starting full GC sweep")

        all_blob_paths: list[Path] = []
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
                deleted_count, blob_paths = self._cleanup_batch_in_session(
                    session, batch
                )
                total_cleaned += deleted_count
                all_blob_paths.extend(blob_paths)

        self._delete_blob_paths(all_blob_paths)
        logger.info(f"GC sweep complete: {total_cleaned} entries cleaned")
        return total_cleaned

    def _delete_blob_paths(self, blob_paths: list[Path]) -> None:
        deleted_count = 0
        for blob_path in blob_paths:
            try:
                blob_path.unlink(missing_ok=True)
                deleted_count += 1
            except OSError:
                logger.warning("Failed to delete orphaned blob: %s", blob_path.name)
        if blob_paths:
            logger.info(
                "Deleted %s/%s orphaned blob file(s) after commit",
                deleted_count,
                len(blob_paths),
            )
