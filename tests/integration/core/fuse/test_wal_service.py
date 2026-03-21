"""
Tests for WalService - database-backed Write-Ahead Log.
"""

import os
import pytest
from datetime import datetime


class TestWalService:
    """Test suite for WalService."""

    @pytest.fixture
    def sample_file_ref(self, file_service):
        """Create a sample FileEntry and FileReference for WAL tests."""
        file_entry = file_service.create_file_entry_with_blobs(
            file_id="test_file_id",
            content_hash="abc123",
            mime_type="text/plain",
            encrypted_size=100,
            original_size=50,
            blob_ids=[],
        )
        file_ref = file_service.create_file_reference(
            name="test.txt",
            parent_id=None,
            file_entry_id=file_entry.id,
        )
        return file_ref

    @pytest.fixture
    def multiple_file_refs(self, file_service):
        """Create multiple FileReferences for recovery tests."""
        refs = []
        for i in range(3):
            file_entry = file_service.create_file_entry_with_blobs(
                file_id=f"file_{i+1}",
                content_hash=f"hash{i}",
                mime_type="text/plain",
                encrypted_size=100,
                original_size=50,
                blob_ids=[],
            )
            file_ref = file_service.create_file_reference(
                name=f"test{i}.txt",
                parent_id=None,
                file_entry_id=file_entry.id,
            )
            refs.append(file_ref)
        return refs

    def test_log_write_creates_entry_and_blob(
        self, wal_service, temp_store, db_session, sample_file_ref
    ):
        """Test that log_write creates a WalEntry and temp blob."""
        file_ref_id = sample_file_ref.id
        chunk_index = 0
        offset = 0
        data = b"Test chunk data"
        file_id = "test_file_id"

        entry = wal_service.log_write(
            file_ref_id=file_ref_id,
            chunk_index=chunk_index,
            offset=offset,
            length=len(data),
            data=data,
            file_id=file_id,
        )

        # Verify entry was created
        assert entry is not None
        assert entry.id is not None
        assert entry.file_reference_id == file_ref_id
        assert entry.chunk_index == chunk_index
        assert entry.offset == offset
        assert entry.length == len(data)
        assert entry.file_id == file_id
        assert entry.flushed is False
        assert entry.temp_blob_id is not None

        # Verify temp blob exists and contains correct data
        blob_data = temp_store.read_temp_blob(
            file_id, chunk_index, entry.temp_blob_id
        )
        assert blob_data == data

    def test_log_multiple_writes(self, wal_service, db_session, sample_file_ref):
        """Test logging multiple writes to the same file."""
        file_ref_id = sample_file_ref.id
        file_id = "multi_write_file"
        chunk_size = 1024

        # Log multiple chunk writes
        entries = []
        for i in range(5):
            entry = wal_service.log_write(
                file_ref_id=file_ref_id,
                chunk_index=i,
                offset=i * chunk_size,
                length=chunk_size,
                data=os.urandom(chunk_size),
                file_id=file_id,
            )
            entries.append(entry)

        # All entries should be unflushed
        pending = wal_service.get_pending_entries(file_ref_id)
        assert len(pending) == 5

        # Dirty chunks should be tracked
        dirty_indices = wal_service.get_dirty_chunk_indices(file_ref_id)
        assert dirty_indices == {0, 1, 2, 3, 4}

    def test_get_pending_entries_empty(self, wal_service, db_session):
        """Test getting pending entries when none exist."""
        entries = wal_service.get_pending_entries(file_ref_id=999)
        assert entries == []

    def test_mark_flushed(self, wal_service, db_session, sample_file_ref):
        """Test marking entries as flushed."""
        file_ref_id = sample_file_ref.id
        file_id = "flush_test"

        # Create some entries
        entry1 = wal_service.log_write(
            file_ref_id=file_ref_id,
            chunk_index=0,
            offset=0,
            length=100,
            data=b"chunk0",
            file_id=file_id,
        )
        entry2 = wal_service.log_write(
            file_ref_id=file_ref_id,
            chunk_index=1,
            offset=100,
            length=100,
            data=b"chunk1",
            file_id=file_id,
        )

        # Mark first entry as flushed
        wal_service.mark_flushed([entry1.id])

        # Check status using a fresh session (services use their own sessions)
        from app.core.database.model.WAL_entry import WalEntry
        verify_session = db_session
        verify_session.expire_all()
        refreshed_entry1 = verify_session.get(WalEntry, entry1.id)
        refreshed_entry2 = verify_session.get(WalEntry, entry2.id)

        assert refreshed_entry1.flushed is True
        assert refreshed_entry1.flushed_at is not None
        assert refreshed_entry2.flushed is False

    def test_checkpoint_deletes_flushed_entries(
        self, wal_service, temp_store, db_session, sample_file_ref
    ):
        """Test that checkpoint deletes flushed entries and temp blobs."""
        file_ref_id = sample_file_ref.id
        file_id = "checkpoint_test"

        # Create entries
        entry1 = wal_service.log_write(
            file_ref_id=file_ref_id,
            chunk_index=0,
            offset=0,
            length=100,
            data=b"chunk0",
            file_id=file_id,
        )
        entry2 = wal_service.log_write(
            file_ref_id=file_ref_id,
            chunk_index=1,
            offset=100,
            length=100,
            data=b"chunk1",
            file_id=file_id,
        )

        blob_id1 = entry1.temp_blob_id
        blob_id2 = entry2.temp_blob_id

        # Mark both as flushed
        wal_service.mark_flushed([entry1.id, entry2.id])

        # Checkpoint
        deleted_count = wal_service.checkpoint(file_ref_id)
        assert deleted_count == 2

        # Entries should be deleted
        pending = wal_service.get_pending_entries(file_ref_id)
        assert len(pending) == 0

        # Temp blobs should be deleted
        assert not (temp_store.tmp_dir / f"{blob_id1}.enc").exists()
        assert not (temp_store.tmp_dir / f"{blob_id2}.enc").exists()

    def test_checkpoint_keeps_unflushed(
        self, wal_service, temp_store, db_session, sample_file_ref
    ):
        """Test that checkpoint only deletes flushed entries."""
        file_ref_id = sample_file_ref.id
        file_id = "partial_checkpoint"

        # Create entries
        entry1 = wal_service.log_write(
            file_ref_id=file_ref_id,
            chunk_index=0,
            offset=0,
            length=100,
            data=b"chunk0",
            file_id=file_id,
        )
        entry2 = wal_service.log_write(
            file_ref_id=file_ref_id,
            chunk_index=1,
            offset=100,
            length=100,
            data=b"chunk1",
            file_id=file_id,
        )

        blob_id1 = entry1.temp_blob_id
        blob_id2 = entry2.temp_blob_id

        # Only mark first as flushed
        wal_service.mark_flushed([entry1.id])

        # Checkpoint
        deleted_count = wal_service.checkpoint(file_ref_id)
        assert deleted_count == 1

        # Second entry should still exist
        pending = wal_service.get_pending_entries(file_ref_id)
        assert len(pending) == 1
        assert pending[0].chunk_index == 1

        # First blob deleted, second still exists
        assert not (temp_store.tmp_dir / f"{blob_id1}.enc").exists()
        assert (temp_store.tmp_dir / f"{blob_id2}.enc").exists()

    def test_get_unflushed_for_recovery(
        self, wal_service, db_session, multiple_file_refs
    ):
        """Test getting unflushed entries grouped by file."""
        # Create entries for multiple files
        for file_ref in multiple_file_refs:
            for i in range(2):
                wal_service.log_write(
                    file_ref_id=file_ref.id,
                    chunk_index=i,
                    offset=i * 100,
                    length=100,
                    data=b"data",
                    file_id=f"file_{file_ref.id}",
                )

        # Get for recovery
        unflushed = wal_service.get_unflushed_for_recovery()

        assert len(unflushed) == 3
        for file_ref in multiple_file_refs:
            assert file_ref.id in unflushed
            assert len(unflushed[file_ref.id]) == 2

    def test_read_chunk_from_wal(self, wal_service, db_session, sample_file_ref):
        """Test reading chunk data from WAL entry."""
        file_ref_id = sample_file_ref.id
        file_id = "read_test"
        original_data = b"Original chunk data for reading"

        entry = wal_service.log_write(
            file_ref_id=file_ref_id,
            chunk_index=0,
            offset=0,
            length=len(original_data),
            data=original_data,
            file_id=file_id,
        )

        # Read back
        read_data = wal_service.read_chunk_from_wal(entry)
        assert read_data == original_data

    def test_get_latest_chunk_entries(self, wal_service, db_session, sample_file_ref):
        """Test getting latest entry per chunk when multiple writes occur."""
        file_ref_id = sample_file_ref.id
        file_id = "latest_test"

        # Write to chunk 0 multiple times
        wal_service.log_write(
            file_ref_id=file_ref_id,
            chunk_index=0,
            offset=0,
            length=100,
            data=b"first write",
            file_id=file_id,
        )
        wal_service.log_write(
            file_ref_id=file_ref_id,
            chunk_index=0,
            offset=0,
            length=100,
            data=b"second write",
            file_id=file_id,
        )
        entry3 = wal_service.log_write(
            file_ref_id=file_ref_id,
            chunk_index=0,
            offset=0,
            length=100,
            data=b"third write",
            file_id=file_id,
        )

        # Also write to chunk 1 once
        entry4 = wal_service.log_write(
            file_ref_id=file_ref_id,
            chunk_index=1,
            offset=100,
            length=100,
            data=b"chunk 1 data",
            file_id=file_id,
        )

        # Get latest entries
        latest = wal_service.get_latest_chunk_entries(file_ref_id)

        assert len(latest) == 2
        assert latest[0].id == entry3.id  # Latest write to chunk 0
        assert latest[1].id == entry4.id  # Only write to chunk 1

    def test_has_pending_writes(self, wal_service, db_session, sample_file_ref):
        """Test checking for pending writes."""
        file_ref_id = sample_file_ref.id
        file_id = "pending_test"

        # No pending initially
        assert wal_service.has_pending_writes(file_ref_id) is False

        # Add a write
        entry = wal_service.log_write(
            file_ref_id=file_ref_id,
            chunk_index=0,
            offset=0,
            length=100,
            data=b"data",
            file_id=file_id,
        )

        # Now has pending
        assert wal_service.has_pending_writes(file_ref_id) is True

        # Mark flushed and checkpoint
        wal_service.mark_flushed([entry.id])
        wal_service.checkpoint(file_ref_id)

        # No longer pending
        assert wal_service.has_pending_writes(file_ref_id) is False

    def test_log_truncate(self, wal_service, db_session, sample_file_ref):
        """Test logging truncate operations."""
        file_ref_id = sample_file_ref.id
        file_id = "truncate_test"
        new_size = 12345

        entry = wal_service.log_truncate(
            file_ref_id=file_ref_id,
            new_size=new_size,
            file_id=file_id,
        )

        assert entry.operation == "truncate"
        assert entry.length == new_size  # new_size stored in length
        assert entry.temp_blob_id == ""  # No blob for truncate

    def test_count_pending(self, wal_service, db_session, multiple_file_refs):
        """Test counting total pending entries."""
        # Initially zero
        assert wal_service.count_pending() == 0

        # Add entries for each file ref
        for file_ref in multiple_file_refs:
            wal_service.log_write(
                file_ref_id=file_ref.id,
                chunk_index=0,
                offset=0,
                length=100,
                data=b"data",
                file_id=f"file_{file_ref.id}",
            )

        assert wal_service.count_pending() == 3

    def test_cleanup_orphaned_blobs(
        self, wal_service, temp_store, db_session, sample_file_ref
    ):
        """Test cleaning up orphaned temp blobs."""
        file_id = "orphan_cleanup_test"
        file_ref_id = sample_file_ref.id

        # Create an entry (blob will be referenced)
        entry = wal_service.log_write(
            file_ref_id=file_ref_id,
            chunk_index=0,
            offset=0,
            length=100,
            data=b"data",
            file_id=file_id,
        )
        valid_blob = entry.temp_blob_id

        # Manually create orphaned blobs (simulating crash scenario)
        orphan_blob = temp_store.write_temp_blob(file_id, 99, b"orphan data")

        # Cleanup should delete orphan but keep valid
        deleted = wal_service.cleanup_orphaned_blobs()
        assert deleted == 1

        # Valid blob still exists
        assert (temp_store.tmp_dir / f"{valid_blob}.enc").exists()
        # Orphan blob deleted
        assert not (temp_store.tmp_dir / f"{orphan_blob}.enc").exists()

