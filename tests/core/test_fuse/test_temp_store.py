"""
Tests for TempStore - encrypted temporary blob storage for WAL.
"""

import os
import pytest
from pathlib import Path


class TestTempStore:
    """Test suite for TempStore."""

    def test_write_and_read_temp_blob(self, temp_store, key_service):
        """Test writing and reading a temp blob."""
        file_id = "test_file_123"
        chunk_index = 0
        plaintext = b"Hello, this is test data for the temp blob!"

        # Write temp blob
        blob_id = temp_store.write_temp_blob(file_id, chunk_index, plaintext)

        assert blob_id is not None
        assert len(blob_id) == 32  # hex string of 16 bytes

        # Verify file exists
        blob_path = temp_store.tmp_dir / f"{blob_id}.enc"
        assert blob_path.exists()

        # Read back
        read_data = temp_store.read_temp_blob(file_id, chunk_index, blob_id)

        assert read_data == plaintext

    def test_write_multiple_chunks(self, temp_store):
        """Test writing multiple chunks for the same file."""
        file_id = "multi_chunk_file"
        chunks = [
            (0, b"Chunk 0 data"),
            (1, b"Chunk 1 data - longer"),
            (2, b"Chunk 2 data - even longer than before"),
        ]

        blob_ids = []
        for chunk_index, data in chunks:
            blob_id = temp_store.write_temp_blob(file_id, chunk_index, data)
            blob_ids.append(blob_id)

        # All blobs should be unique
        assert len(set(blob_ids)) == len(blob_ids)

        # Read back and verify
        for (chunk_index, expected_data), blob_id in zip(chunks, blob_ids):
            read_data = temp_store.read_temp_blob(file_id, chunk_index, blob_id)
            assert read_data == expected_data

    def test_read_nonexistent_blob(self, temp_store):
        """Test reading a blob that doesn't exist."""
        result = temp_store.read_temp_blob(
            file_id="any",
            chunk_index=0,
            blob_id="nonexistent_blob_id",
        )
        assert result is None

    def test_delete_temp_blob(self, temp_store):
        """Test deleting a temp blob."""
        file_id = "delete_test"
        blob_id = temp_store.write_temp_blob(file_id, 0, b"Delete me")

        blob_path = temp_store.tmp_dir / f"{blob_id}.enc"
        assert blob_path.exists()

        # Delete
        result = temp_store.delete_temp_blob(blob_id)
        assert result is True
        assert not blob_path.exists()

        # Delete again should return False
        result = temp_store.delete_temp_blob(blob_id)
        assert result is False

    def test_cleanup_orphaned_blobs(self, temp_store):
        """Test cleaning up orphaned blobs."""
        file_id = "orphan_test"

        # Write some blobs
        valid_blob = temp_store.write_temp_blob(file_id, 0, b"Valid blob")
        orphan1 = temp_store.write_temp_blob(file_id, 1, b"Orphan 1")
        orphan2 = temp_store.write_temp_blob(file_id, 2, b"Orphan 2")

        # Only valid_blob is "referenced"
        valid_blob_ids = {valid_blob}

        # Clean up orphans
        deleted_count = temp_store.cleanup_orphaned(valid_blob_ids)
        assert deleted_count == 2

        # Valid blob should still exist
        assert (temp_store.tmp_dir / f"{valid_blob}.enc").exists()

        # Orphans should be deleted
        assert not (temp_store.tmp_dir / f"{orphan1}.enc").exists()
        assert not (temp_store.tmp_dir / f"{orphan2}.enc").exists()

    def test_get_all_blob_ids(self, temp_store):
        """Test getting all blob IDs on disk."""
        file_id = "all_blobs_test"

        blob1 = temp_store.write_temp_blob(file_id, 0, b"Blob 1")
        blob2 = temp_store.write_temp_blob(file_id, 1, b"Blob 2")

        all_ids = temp_store.get_all_blob_ids()

        assert blob1 in all_ids
        assert blob2 in all_ids

    def test_large_chunk_data(self, temp_store):
        """Test writing and reading a large chunk."""
        file_id = "large_chunk"
        chunk_index = 0
        # 64KB of random data (typical chunk size)
        plaintext = os.urandom(64 * 1024)

        blob_id = temp_store.write_temp_blob(file_id, chunk_index, plaintext)
        read_data = temp_store.read_temp_blob(file_id, chunk_index, blob_id)

        assert read_data == plaintext

    def test_different_file_ids_same_chunk(self, temp_store):
        """Test that different file IDs produce different encryption."""
        chunk_index = 0
        data = b"Same data for both files"

        blob1 = temp_store.write_temp_blob("file_a", chunk_index, data)
        blob2 = temp_store.write_temp_blob("file_b", chunk_index, data)

        # Read back should work for correct file_id
        assert temp_store.read_temp_blob("file_a", chunk_index, blob1) == data
        assert temp_store.read_temp_blob("file_b", chunk_index, blob2) == data

        # Reading with wrong file_id should fail (authentication error)
        with pytest.raises(Exception):
            temp_store.read_temp_blob("file_b", chunk_index, blob1)

    def test_wrong_chunk_index_fails(self, temp_store):
        """Test that wrong chunk index fails authentication."""
        file_id = "chunk_index_test"
        data = b"Test data"

        blob_id = temp_store.write_temp_blob(file_id, chunk_index=5, plaintext=data)

        # Correct chunk index works
        assert temp_store.read_temp_blob(file_id, 5, blob_id) == data

        # Wrong chunk index should fail authentication
        with pytest.raises(Exception):
            temp_store.read_temp_blob(file_id, 6, blob_id)

