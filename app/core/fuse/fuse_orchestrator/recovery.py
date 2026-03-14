from typing import Dict

from app.core.database.model.WAL_entry import WalEntry
from app.core.fuse.chunk_store import ChunkStore

from .runtime import get_runtime_module


class RecoveryMixin:
    def _check_and_recover(self) -> None:
        """Clean orphaned blobs and replay any unflushed WAL entries from a previous
        run."""
        rt = get_runtime_module()

        try:
            cleaned = self.wal_service.cleanup_orphaned_blobs()
            if cleaned > 0:
                rt.logger.info(f"Recovery: cleaned up {cleaned} orphaned temp blobs")
        except Exception as e:
            rt.logger.warning(f"Recovery: error cleaning orphaned blobs: {e}")

        try:
            pending_by_file = self.wal_service.get_unflushed_for_recovery()
            if not pending_by_file:
                return

            rt.logger.info(
                f"Recovery: replaying WAL entries for {len(pending_by_file)} file(s)"
            )

            all_entry_ids = []
            for file_ref_id, entries in pending_by_file.items():
                try:
                    self._replay_entries_for_file(file_ref_id, entries)
                    all_entry_ids.extend(e.id for e in entries)
                except Exception as e:
                    rt.logger.error(
                        f"Recovery: failed to replay entries for "
                        f"file_ref_id={file_ref_id}: {e}",
                        exc_info=True,
                    )

            if all_entry_ids:
                self.wal_service.mark_flushed(all_entry_ids)
                for file_ref_id in pending_by_file:
                    self.wal_service.checkpoint(file_ref_id)
        except Exception as e:
            rt.logger.error(f"Recovery: unexpected error: {e}", exc_info=True)

    def _replay_entries_for_file(
        self, file_ref_id: int, entries: list[WalEntry]
    ) -> None:
        """Reconstruct and flush dirty chunks for a file from its WAL entries."""
        rt = get_runtime_module()
        file_ref = self.file_service.get_file_reference_with_blobs(file_ref_id)
        if not file_ref:
            rt.logger.warning(
                f"Recovery: skipping file_ref_id = {file_ref_id} [not found in DB]"
            )
            return

        file_entry = file_ref.file_entry
        if not file_entry:
            rt.logger.warning(
                f"Recovery: skipping file_ref_id = {file_ref_id} [no file_entry found]"
            )
            return

        blob_ids = sorted(
            [b.blob_id for b in file_entry.blobs],
            key=lambda bid: next(
                b.blob_index for b in file_entry.blobs if b.blob_id == bid
            ),
        )

        chunk_store = ChunkStore(
            vault_path=self.vault_path,
            cache_dir=self.cache_dir,
            key_service=self.key_service,
            vault_id=self.vault_id,
            file_service=self.file_service,
            folder_service=self.folder_service,
            gc=self.gc,
        )
        chunk_store.load_blob_index(file_entry.file_id, blob_ids)

        latest_per_chunk: Dict[int, WalEntry] = {}
        for entry in entries:
            if entry.operation == "write":
                latest_per_chunk[entry.chunk_index] = entry

        dirty_chunks: Dict[int, bytearray] = {}
        for chunk_idx, entry in latest_per_chunk.items():
            data = self.wal_service.read_chunk_from_wal(entry)
            if data is not None:
                dirty_chunks[chunk_idx] = (
                    bytearray(data) if isinstance(data, bytes) else data
                )

        if dirty_chunks:
            chunk_store.flush_to_blobs(
                file_id=file_entry.file_id,
                file_ref_id=file_ref_id,
                dirty_chunks=dirty_chunks,
                original_size=file_entry.original_size_bytes,
            )
            rt.logger.info(
                f"Recovery: replayed {len(dirty_chunks)} chunk(s) "
                f"for file_ref_id={file_ref_id}"
            )
