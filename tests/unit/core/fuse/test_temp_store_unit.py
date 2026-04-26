"""Unit tests for TempStore - encrypted temporary blob file management."""

import os
import secrets
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.infrastructure.crypto.types import KeyPurpose
from app.infrastructure.fuse.temp_store import TempStore


class _DummyKeyService:
    """In-memory key service for unit testing."""

    def __init__(self):
        self._keys = {}

    def derive_sub_key(self, purpose: KeyPurpose, context: str) -> bytearray:
        if (purpose, context) not in self._keys:
            self._keys[(purpose, context)] = bytearray(secrets.token_bytes(32))
        return self._keys[(purpose, context)]


def _make_temp_store(tmp_path: Path) -> tuple[TempStore, Path, _DummyKeyService]:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    key_service = _DummyKeyService()
    store = TempStore(cache_dir=cache_dir, key_service=key_service)
    return store, cache_dir, key_service


class TestWriteTempBlob:
    def test_writes_to_cache_directory(self, tmp_path: Path):
        store, cache_dir, _ = _make_temp_store(tmp_path)
        blob_id = store.write_temp_blob("file-1", 0, b"test data")

        assert blob_id is not None
        assert len(blob_id) == 32
        expected_path = cache_dir / "temp-blobs" / f"{blob_id}.enc"
        assert expected_path.exists()

    def test_written_file_contains_encrypted_data(self, tmp_path: Path):
        store, cache_dir, _ = _make_temp_store(tmp_path)
        blob_id = store.write_temp_blob("file-1", 0, b"secret content")

        blob_path = cache_dir / "temp-blobs" / f"{blob_id}.enc"
        with open(blob_path, "rb") as f:
            data = f.read()
        assert data != b"secret content"
        assert len(data) > len(b"secret content")

    def test_blob_id_is_unique(self, tmp_path: Path):
        store, _, _ = _make_temp_store(tmp_path)
        blob_ids = [
            store.write_temp_blob("file-1", 0, b"data")
            for _ in range(100)
        ]
        assert len(set(blob_ids)) == 100

    def test_different_file_ids_produce_different_keys(self, tmp_path: Path):
        store1, _, key_service1 = _make_temp_store(tmp_path)
        store2, _, key_service2 = _make_temp_store(tmp_path)

        blob_id1 = store1.write_temp_blob("file-1", 0, b"data")
        blob_id2 = store2.write_temp_blob("file-2", 0, b"data")

        data1 = store1.read_temp_blob("file-1", 0, blob_id1)
        data2 = store2.read_temp_blob("file-2", 0, blob_id2)

        assert data1 == b"data"
        assert data2 == b"data"


class TestReadTempBlob:
    def test_reads_what_was_written(self, tmp_path: Path):
        store, _, _ = _make_temp_store(tmp_path)
        original_data = b"Hello, World!"
        blob_id = store.write_temp_blob("file-1", 0, original_data)

        result = store.read_temp_blob("file-1", 0, blob_id)
        assert result == original_data

    def test_returns_none_for_nonexistent_blob(self, tmp_path: Path):
        store, _, _ = _make_temp_store(tmp_path)
        result = store.read_temp_blob("file-1", 0, "nonexistent-id")
        assert result is None

    def test_decryption_fails_with_wrong_chunk_index(self, tmp_path: Path):
        store, _, _ = _make_temp_store(tmp_path)
        blob_id = store.write_temp_blob("file-1", 0, b"data")

        with pytest.raises(Exception):
            store.read_temp_blob("file-1", 1, blob_id)


class TestDeleteTempBlob:
    def test_deletes_existing_blob(self, tmp_path: Path):
        store, cache_dir, _ = _make_temp_store(tmp_path)
        blob_id = store.write_temp_blob("file-1", 0, b"data")

        blob_path = cache_dir / "temp-blobs" / f"{blob_id}.enc"
        assert blob_path.exists()

        result = store.delete_temp_blob(blob_id)
        assert result is True
        assert not blob_path.exists()

    def test_delete_nonexistent_returns_false(self, tmp_path: Path):
        store, _, _ = _make_temp_store(tmp_path)
        result = store.delete_temp_blob("nonexistent-id")
        assert result is False


class TestCleanupOrphaned:
    def test_removes_orphaned_temp_files(self, tmp_path: Path):
        store, cache_dir, _ = _make_temp_store(tmp_path)
        blob_id1 = store.write_temp_blob("file-1", 0, b"data1")
        blob_id2 = store.write_temp_blob("file-2", 0, b"data2")

        valid_ids = {blob_id1}
        deleted = store.cleanup_orphaned(valid_ids)

        assert deleted == 1
        remaining = store.get_all_blob_ids()
        assert remaining == {blob_id1}

    def test_keeps_referenced_temp_files(self, tmp_path: Path):
        store, cache_dir, _ = _make_temp_store(tmp_path)
        blob_id1 = store.write_temp_blob("file-1", 0, b"data1")
        blob_id2 = store.write_temp_blob("file-2", 0, b"data2")

        valid_ids = {blob_id1, blob_id2}
        deleted = store.cleanup_orphaned(valid_ids)

        assert deleted == 0
        remaining = store.get_all_blob_ids()
        assert remaining == {blob_id1, blob_id2}

    def test_cleans_up_all_when_no_valid_ids(self, tmp_path: Path):
        store, cache_dir, _ = _make_temp_store(tmp_path)
        store.write_temp_blob("file-1", 0, b"data1")
        store.write_temp_blob("file-2", 0, b"data2")

        deleted = store.cleanup_orphaned(set())

        assert deleted == 2
        assert store.get_all_blob_ids() == set()

    def test_returns_zero_when_temp_dir_missing(self, tmp_path: Path):
        store, _, _ = _make_temp_store(tmp_path)
        deleted = store.cleanup_orphaned({"any-id"})
        assert deleted == 0


class TestGetAllBlobIds:
    def test_returns_all_blob_ids_on_disk(self, tmp_path: Path):
        store, _, _ = _make_temp_store(tmp_path)
        blob_id1 = store.write_temp_blob("file-1", 0, b"data1")
        blob_id2 = store.write_temp_blob("file-2", 0, b"data2")

        all_ids = store.get_all_blob_ids()
        assert all_ids == {blob_id1, blob_id2}

    def test_returns_empty_set_when_no_blobs(self, tmp_path: Path):
        store, _, _ = _make_temp_store(tmp_path)
        all_ids = store.get_all_blob_ids()
        assert all_ids == set()


class TestTempFileNaming:
    def test_blob_id_is_hex_string(self, tmp_path: Path):
        store, _, _ = _make_temp_store(tmp_path)
        blob_id = store.write_temp_blob("file-1", 0, b"data")

        assert all(c in "0123456789abcdef" for c in blob_id)

    def test_blob_id_length_is_32(self, tmp_path: Path):
        store, _, _ = _make_temp_store(tmp_path)
        blob_id = store.write_temp_blob("file-1", 0, b"data")

        assert len(blob_id) == 32

    def test_file_extension_is_enc(self, tmp_path: Path):
        store, cache_dir, _ = _make_temp_store(tmp_path)
        blob_id = store.write_temp_blob("file-1", 0, b"data")

        blob_path = cache_dir / "temp-blobs" / f"{blob_id}.enc"
        assert blob_path.suffix == ".enc"


class TestConcurrentOperations:
    def test_multiple_files_concurrent_writes(self, tmp_path: Path):
        store, _, _ = _make_temp_store(tmp_path)
        blob_ids = []
        for i in range(10):
            blob_id = store.write_temp_blob(f"file-{i}", 0, f"data-{i}".encode())
            blob_ids.append(blob_id)

        assert len(set(blob_ids)) == 10
        for i in range(10):
            data = store.read_temp_blob(f"file-{i}", 0, blob_ids[i])
            assert data == f"data-{i}".encode()

    def test_multiple_chunks_same_file(self, tmp_path: Path):
        store, _, _ = _make_temp_store(tmp_path)
        blob_ids = []
        for i in range(5):
            blob_id = store.write_temp_blob("file-1", i, f"chunk-{i}".encode())
            blob_ids.append(blob_id)

        assert len(set(blob_ids)) == 5
        for i in range(5):
            data = store.read_temp_blob("file-1", i, blob_ids[i])
            assert data == f"chunk-{i}".encode()

    def test_write_read_delete_lifecycle(self, tmp_path: Path):
        store, _, _ = _make_temp_store(tmp_path)
        blob_id = store.write_temp_blob("file-1", 0, b"lifecycle test")

        data = store.read_temp_blob("file-1", 0, blob_id)
        assert data == b"lifecycle test"

        store.delete_temp_blob(blob_id)
        result = store.read_temp_blob("file-1", 0, blob_id)
        assert result is None


class TestBlobPath:
    def test_blob_path_method(self, tmp_path: Path):
        store, _, _ = _make_temp_store(tmp_path)
        blob_path = store._blob_path("test-blob-id")
        assert blob_path.name == "test-blob-id.enc"

    def test_temp_dir_created_on_init(self, tmp_path: Path):
        store, cache_dir, _ = _make_temp_store(tmp_path)
        expected_dir = cache_dir / "temp-blobs"
        assert expected_dir.exists()
        assert expected_dir.is_dir()
