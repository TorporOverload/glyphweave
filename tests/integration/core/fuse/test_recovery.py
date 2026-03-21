"""Crash-recovery tests for the WAL-backed single-file workflow."""

import os


class TestWalPreservesWrites:
    def test_wal_entries_readable_after_crash(self, recovery_fs):
        """Releasing without a flush should leave readable WAL entries behind."""
        fs, _ = recovery_fs
        new_data = b"Data written before crash"

        # Write
        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)
        fs.write(f"/{fs.file_name}", new_data, 0, fh)

        # Verify WAL has entries
        assert fs.wal_service.has_pending_writes(fs.file_ref_id)

        # Simulate crash: release handle without blob flush
        fs.handle_manager.release(fh, flush=False)
        fs._open_count = 0

        # WAL entries should still be readable
        entries = fs.wal_service.get_pending_entries(fs.file_ref_id)
        assert len(entries) >= 1

        # Read chunk data back from WAL
        for entry in entries:
            data = fs.wal_service.read_chunk_from_wal(entry)
            assert data is not None
            assert len(data) > 0


class TestRecoverFromWal:
    def test_recover_single_chunk(self, recovery_fs, file_service):
        """Write one chunk, simulate crash, recover from WAL, verify file content."""
        fs, original_content = recovery_fs
        new_data = b"Recovered chunk data!"

        # Write phase
        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)
        fs.write(f"/{fs.file_name}", new_data, 0, fh)

        # Simulate crash
        fs.handle_manager.release(fh, flush=False)
        fs._open_count = 0

        # Recovery: get latest chunk entries from WAL (dict: chunk_index -> WalEntry)
        latest = fs.wal_service.get_latest_chunk_entries(fs.file_ref_id)
        assert len(latest) >= 1

        # Build dirty chunks from WAL
        dirty_chunks = {}
        for chunk_idx, entry in latest.items():
            data = fs.wal_service.read_chunk_from_wal(entry)
            dirty_chunks[chunk_idx] = bytearray(data)

        # Flush recovered chunks
        fs.chunk_store.flush_to_blobs(
            file_id=fs.file_id,
            file_ref_id=fs.file_ref_id,
            dirty_chunks=dirty_chunks,
            original_size=len(new_data),
        )
        fs._refresh_after_flush()

        # Verify: open and read back
        fh2 = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        data = fs.read(f"/{fs.file_name}", len(new_data) + 100, 0, fh2)
        assert data == new_data
        fs.release(f"/{fs.file_name}", fh2)

    def test_recover_multiple_chunks(self, recovery_fs, file_service):
        """Write to multiple chunks, crash, recover all, verify complete content."""
        fs, original_content = recovery_fs
        chunk_size = fs.chunk_size

        # Create content spanning multiple chunks
        new_content = os.urandom(chunk_size * 2 + 100)  # 2.x chunks

        # Write phase
        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)
        fs.write(f"/{fs.file_name}", new_content, 0, fh)
        fs.truncate(f"/{fs.file_name}", len(new_content), fh)

        # Simulate crash
        fs.handle_manager.release(fh, flush=False)
        fs._open_count = 0

        # Recovery
        latest = fs.wal_service.get_latest_chunk_entries(fs.file_ref_id)
        dirty_chunks = {}
        for chunk_idx, entry in latest.items():
            data = fs.wal_service.read_chunk_from_wal(entry)
            dirty_chunks[chunk_idx] = bytearray(data)

        fs.chunk_store.flush_to_blobs(
            file_id=fs.file_id,
            file_ref_id=fs.file_ref_id,
            dirty_chunks=dirty_chunks,
            original_size=len(new_content),
        )
        fs._refresh_after_flush()

        # Verify full content
        fh2 = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        data = bytearray()
        offset = 0
        while offset < len(new_content):
            chunk = fs.read(f"/{fs.file_name}", chunk_size, offset, fh2)
            if not chunk:
                break
            data.extend(chunk)
            offset += len(chunk)
        assert bytes(data) == new_content
        fs.release(f"/{fs.file_name}", fh2)


class TestLatestWriteWins:
    def test_multiple_writes_same_chunk_recovery_gets_latest(self, recovery_fs):
        """Recovery should surface only the newest WAL entry for a chunk."""
        fs, original_content = recovery_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)
        fs.write(f"/{fs.file_name}", b"first write data!!", 0, fh)
        fs.write(f"/{fs.file_name}", b"second write data!", 0, fh)
        final_data = b"third and final!!!"
        fs.write(f"/{fs.file_name}", final_data, 0, fh)

        # Simulate crash
        fs.handle_manager.release(fh, flush=False)
        fs._open_count = 0

        # Get latest entries - should have only the latest per chunk
        latest = fs.wal_service.get_latest_chunk_entries(fs.file_ref_id)

        # Only one entry for chunk 0 (the latest)
        assert 0 in latest
        assert len([idx for idx in latest if idx == 0]) == 1

        # Recovered chunk should start with the final write data
        # (the chunk includes the full chunk content after the partial write merge)
        recovered = fs.wal_service.read_chunk_from_wal(latest[0])
        assert recovered[: len(final_data)] == final_data


class TestCheckpointAfterRecovery:
    def test_checkpoint_cleans_wal(self, recovery_fs):
        """A completed recovery should checkpoint the WAL back to an empty state."""
        fs, _ = recovery_fs
        new_data = b"Data for checkpoint test"

        # Write and crash
        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)
        fs.write(f"/{fs.file_name}", new_data, 0, fh)
        fs.handle_manager.release(fh, flush=False)
        fs._open_count = 0

        assert fs.wal_service.has_pending_writes(fs.file_ref_id)

        # Recover
        latest = fs.wal_service.get_latest_chunk_entries(fs.file_ref_id)
        dirty_chunks = {}
        for chunk_idx, entry in latest.items():
            data = fs.wal_service.read_chunk_from_wal(entry)
            dirty_chunks[chunk_idx] = bytearray(data)

        fs.chunk_store.flush_to_blobs(
            file_id=fs.file_id,
            file_ref_id=fs.file_ref_id,
            dirty_chunks=dirty_chunks,
            original_size=len(new_data),
        )
        fs._refresh_after_flush()

        # Mark flushed and checkpoint
        entries = fs.wal_service.get_pending_entries(fs.file_ref_id)
        fs.wal_service.mark_flushed([e.id for e in entries])
        fs.wal_service.checkpoint(fs.file_ref_id)

        # WAL should be clean
        assert not fs.wal_service.has_pending_writes(fs.file_ref_id)
        assert fs.wal_service.count_pending() == 0
