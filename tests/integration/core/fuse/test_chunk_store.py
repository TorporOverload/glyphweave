"""
End-to-end tests for ChunkStore with real encryption, DB, and blob files.
"""

import hashlib
import math
import secrets

import pytest

from app.core.crypto.constants import FUSE_CHUNK_SIZE
from app.core.vault_layout import resolve_blob_path
from tests.support.fuse_builders import ordered_blob_ids


@pytest.fixture
def chunk_store_with_file(
    encrypted_file_in_vault,
    chunk_store,
):
    """ChunkStore with a loaded blob index from an encrypted file."""
    file_ref, original_content = encrypted_file_in_vault
    entry = file_ref.file_entry
    chunk_store.load_blob_index(entry.file_id, ordered_blob_ids(entry))

    return chunk_store, entry.file_id, file_ref.id, original_content


@pytest.fixture
def chunk_store_with_large_file(
    encrypted_large_file_in_vault,
    chunk_store,
):
    """ChunkStore with a loaded blob index from a large multi-blob file."""
    file_ref, original_content = encrypted_large_file_in_vault
    entry = file_ref.file_entry
    chunk_store.load_blob_index(entry.file_id, ordered_blob_ids(entry))

    return chunk_store, entry.file_id, file_ref.id, original_content


class TestLoadBlobIndex:
    def test_populates_indices(self, chunk_store_with_file):
        store, file_id, _, original_content = chunk_store_with_file

        index = store._indices[file_id]
        expected_chunks = math.ceil(len(original_content) / FUSE_CHUNK_SIZE)
        assert index.chunk_count == expected_chunks

    def test_multi_blob_large_file(self, chunk_store_with_large_file):
        store, file_id, _, original_content = chunk_store_with_large_file

        index = store._indices[file_id]
        expected_chunks = math.ceil(len(original_content) / FUSE_CHUNK_SIZE)
        assert index.chunk_count == expected_chunks
        # Verify all chunks are indexed
        for i in range(expected_chunks):
            assert index.get(i) is not None


class TestReadChunk:
    def test_decrypts_first_chunk(self, chunk_store_with_file):
        store, file_id, _, original_content = chunk_store_with_file

        chunk = store.read_chunk(file_id, 0)
        expected = original_content[: FUSE_CHUNK_SIZE]
        assert chunk == expected

    def test_read_all_chunks_reassembles_file(self, chunk_store_with_large_file):
        store, file_id, _, original_content = chunk_store_with_large_file

        index = store._indices[file_id]
        data = bytearray()
        for i in range(index.chunk_count):
            chunk = store.read_chunk(file_id, i)
            assert chunk is not None
            data.extend(chunk)

        assert bytes(data[: len(original_content)]) == original_content

    def test_invalid_index_returns_none(self, chunk_store_with_file):
        store, file_id, _, _ = chunk_store_with_file
        assert store.read_chunk(file_id, 99999) is None

    def test_unknown_file_id_returns_none(self, chunk_store_with_file):
        store, _, _, _ = chunk_store_with_file
        assert store.read_chunk("nonexistent_file_id", 0) is None


class TestFlushToBlobs:
    def test_flush_and_readback(self, chunk_store_with_file, file_service):
        """Modify a chunk, flush, reload index, read back modified data."""
        store, file_id, file_ref_id, original_content = chunk_store_with_file

        # Modify chunk 0
        new_chunk_data = b"MODIFIED CHUNK DATA " + b"X" * 30
        dirty_chunks = {0: bytearray(new_chunk_data)}

        store.flush_to_blobs(
            file_id=file_id,
            file_ref_id=file_ref_id,
            dirty_chunks=dirty_chunks,
            original_size=len(new_chunk_data),
        )

        # Reload from DB to get updated FileReference
        file_ref = file_service.get_file_reference_with_blobs(file_ref_id)
        new_entry = file_ref.file_entry
        new_blob_ids = sorted(
            [b.blob_id for b in new_entry.blobs],
            key=lambda bid: next(
                b.blob_index for b in new_entry.blobs if b.blob_id == bid
            ),
        )

        # Reload index with new file_id
        store.load_blob_index(new_entry.file_id, new_blob_ids)

        # Read back modified chunk
        chunk = store.read_chunk(new_entry.file_id, 0)
        assert chunk == new_chunk_data

    def test_flush_creates_new_file_entry(self, chunk_store_with_file, file_service):
        """After flush, FileReference points to a new FileEntry."""
        store, file_id, file_ref_id, original_content = chunk_store_with_file

        # Get original entry id
        original_ref = file_service.get_file_reference_with_blobs(file_ref_id)
        original_entry_id = original_ref.file_entry_id

        # Modify and flush
        dirty_chunks = {0: bytearray(b"different content than original")}
        store.flush_to_blobs(
            file_id=file_id,
            file_ref_id=file_ref_id,
            dirty_chunks=dirty_chunks,
            original_size=len(b"different content than original"),
        )

        # Check new entry
        updated_ref = file_service.get_file_reference_with_blobs(file_ref_id)
        assert updated_ref.file_entry_id != original_entry_id

    def test_flush_gc_old_entry(
        self, chunk_store_with_file, file_service, temp_vault_path
    ):
        """After flush, old blob files are garbage collected."""
        store, file_id, file_ref_id, original_content = chunk_store_with_file

        # Get old blob paths
        old_ref = file_service.get_file_reference_with_blobs(file_ref_id)
        old_blob_ids = [b.blob_id for b in old_ref.file_entry.blobs]
        old_blob_paths = [
            resolve_blob_path(temp_vault_path, bid) for bid in old_blob_ids
        ]
        for p in old_blob_paths:
            assert p.exists()

        # Modify and flush
        dirty_chunks = {0: bytearray(b"new data for gc test")}
        store.flush_to_blobs(
            file_id=file_id,
            file_ref_id=file_ref_id,
            dirty_chunks=dirty_chunks,
            original_size=len(b"new data for gc test"),
        )

        # Old blobs should be gone
        for p in old_blob_paths:
            assert not p.exists(), f"Old blob not GC'd: {p}"

    def test_flush_dedup_reuses_entry(self, chunk_store_with_file, file_service):
        """Flushing identical content reuses the existing FileEntry (dedup)."""
        store, file_id, file_ref_id, original_content = chunk_store_with_file

        # Flush the exact same content
        num_chunks = math.ceil(len(original_content) / FUSE_CHUNK_SIZE)
        dirty_chunks = {}
        for i in range(num_chunks):
            start = i * FUSE_CHUNK_SIZE
            end = min(start + FUSE_CHUNK_SIZE, len(original_content))
            dirty_chunks[i] = bytearray(original_content[start:end])

        original_ref = file_service.get_file_reference_with_blobs(file_ref_id)
        original_entry_id = original_ref.file_entry_id

        store.flush_to_blobs(
            file_id=file_id,
            file_ref_id=file_ref_id,
            dirty_chunks=dirty_chunks,
            original_size=len(original_content),
        )

        # Should reuse same entry (dedup hit)
        updated_ref = file_service.get_file_reference_with_blobs(file_ref_id)
        assert updated_ref.file_entry_id == original_entry_id


class TestAssembleFullContent:
    def test_merges_dirty_and_clean(self, chunk_store_with_large_file):
        """Merged reads should preserve untouched chunks while overlaying dirty ones."""
        store, file_id, _, original_content = chunk_store_with_large_file

        # Only modify chunk 1, leave chunk 0 clean (from blob)
        new_chunk_1 = b"Y" * FUSE_CHUNK_SIZE
        dirty_chunks = {1: bytearray(new_chunk_1)}

        result = store._assemble_full_content(
            file_id=file_id,
            dirty_chunks=dirty_chunks,
            total_size=len(original_content),
        )

        # Chunk 0 should be from original, chunk 1 should be modified
        assert result[: FUSE_CHUNK_SIZE] == original_content[: FUSE_CHUNK_SIZE]
        assert result[FUSE_CHUNK_SIZE : 2 * FUSE_CHUNK_SIZE] == new_chunk_1


class TestEncryptAndStore:
    def test_creates_blobs_on_disk(self, chunk_store, temp_vault_path):
        """_encrypt_and_store creates blob files and a DB entry."""
        plaintext = b"Test data for encrypt_and_store"
        content_hash = hashlib.sha256(plaintext).hexdigest()

        entry = chunk_store._encrypt_and_store(
            plaintext=plaintext,
            file_id=secrets.token_hex(16),
            content_hash=content_hash,
            mime_type="text/plain",
        )

        assert entry is not None
        assert entry.id is not None
        # Blob files should exist on disk
        blobs = chunk_store.file_service.get_file_entry_by_file_id(entry.file_id)
        for blob in blobs.blobs:
            blob_path = resolve_blob_path(temp_vault_path, blob.blob_id)
            assert blob_path.exists()
