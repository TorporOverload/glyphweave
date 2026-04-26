"""Unit tests for ChunkStore - blob-backed chunk storage with encryption."""

import pytest
from pathlib import Path
from types import SimpleNamespace
from io import BytesIO
from unittest.mock import MagicMock, patch, Mock

from app.infrastructure.fuse.chunk_store import ChunkStore
from app.infrastructure.crypto.constants import FUSE_CHUNK_SIZE


class _DummyChunkStore:
    """In-memory chunk store for unit testing."""

    def __init__(self):
        self.writes = []
        self.chunks = {}
        self.metadata_writes = []
        self.truncates = []

    def read_chunk(self, file_id: str, chunk_index: int):
        return self.chunks.get((file_id, chunk_index))

    def write_chunk(self, file_id: str, chunk_index: int, data: bytes) -> None:
        self.writes.append((file_id, chunk_index, data))
        self.chunks[(file_id, chunk_index)] = data

    def write_metadata(self, file_id: str, metadata) -> None:
        self.metadata_writes.append((file_id, metadata))

    def truncate_chunks(self, file_id: str, new_size: int) -> None:
        self.truncates.append((file_id, new_size))


def _make_chunk_store(chunk_size=FUSE_CHUNK_SIZE, **kwargs):
    mock_key_service = Mock()
    mock_key_service.derive_sub_key = Mock(return_value=bytearray(b"x" * 32))
    mock_key_service.master_key = Mock()
    mock_key_service.master_key.view = Mock(return_value=b"x" * 32)

    mock_file_service = Mock()
    mock_folder_service = Mock()
    mock_gc = Mock()

    store = ChunkStore(
        vault_path=kwargs.get("vault_path", Path("/fake/vault")),
        cache_dir=kwargs.get("cache_dir", Path("/fake/cache")),
        key_service=mock_key_service,
        vault_id=kwargs.get("vault_id", b"test_vault"),
        file_service=mock_file_service,
        folder_service=mock_folder_service,
        gc=mock_gc,
        chunk_size=chunk_size,
    )
    return store


class TestChunkStoreInit:
    def test_initializes_with_required_dependencies(self):
        store = _make_chunk_store(
            vault_path=Path("/test/vault"),
            cache_dir=Path("/test/cache"),
            vault_id=b"test_vault_123",
        )

        assert store.vault_path == Path("/test/vault")
        assert store.cache_dir == Path("/test/cache")
        assert store.vault_id == b"test_vault_123"
        assert store.chunk_size == FUSE_CHUNK_SIZE
        assert store.encryption_service is not None
        assert store._indices == {}
        assert store._key_cache == {}

    def test_default_chunk_size_is_fuse_chunk_size(self):
        store = _make_chunk_store()
        assert store.chunk_size == FUSE_CHUNK_SIZE

    def test_custom_chunk_size(self):
        custom_chunk_size = 8192
        store = _make_chunk_store(chunk_size=custom_chunk_size)
        assert store.chunk_size == custom_chunk_size


class TestKeyCache:
    def test_get_file_key_derives_and_caches(self):
        store = _make_chunk_store()
        file_id = "test_file_123"

        key1 = store._get_file_key(file_id)
        assert key1 is not None

        key2 = store._get_file_key(file_id)
        assert key2 is key1

        assert file_id in store._key_cache
        store.key_service.derive_sub_key.assert_called()

    def test_clear_key_cache_zeros_and_clears(self):
        store = _make_chunk_store()
        file_id = "test_file_456"
        store._get_file_key(file_id)
        assert len(store._key_cache) == 1

        store.clear_key_cache()
        assert len(store._key_cache) == 0


class TestFlushBlobsUsesEncryptionService:
    def test_flush_to_blobs_calls_encryption_service(self):
        store = _make_chunk_store(vault_path=Path("/test/vault"))

        captured_calls = []

        def mock_encrypt_file(*, file_path, vault_path, master_key, vault_id, file_id):
            captured_calls.append({
                "file_path": file_path,
                "vault_path": vault_path,
                "master_key": master_key,
                "vault_id": vault_id,
                "file_id": file_id,
            })
            return []

        store.encryption_service.encrypt_file = mock_encrypt_file

        file_ref = SimpleNamespace(id=1, file_entry_id=1)
        store.folder_service.get_by_id = Mock(return_value=file_ref)
        store.file_service.find_by_content_hash = Mock(return_value=None)
        store.file_service.create_file_entry_with_blobs = Mock(return_value=SimpleNamespace(id=2))
        store.file_service.update_file_reference_entry = Mock(return_value=None)

        store.flush_to_blobs(
            file_id="file_abc",
            file_ref_id=1,
            dirty_chunks={0: bytearray(b"test data")},
            original_size=9,
            mime_type="text/plain",
        )

        assert len(captured_calls) == 1
        assert isinstance(captured_calls[0]["file_path"], BytesIO)
        assert captured_calls[0]["vault_path"] == Path("/test/vault")


class TestStagePlaintextBufferUsesRuntimeCache:
    def test_encrypt_and_store_uses_bytesio_buffer(self):
        store = _make_chunk_store(vault_path=Path("/test/vault"))

        captured_file_path = None

        def mock_encrypt_file(*, file_path, vault_path, master_key, vault_id, file_id):
            nonlocal captured_file_path
            captured_file_path = file_path
            return []

        store.encryption_service.encrypt_file = mock_encrypt_file
        store.file_service.create_file_entry_with_blobs = Mock(return_value=SimpleNamespace(id=1))

        plaintext = b"runtime cached plaintext data"
        store._encrypt_and_store(
            plaintext=plaintext,
            file_id="new_file_id",
            content_hash="abc123",
            mime_type="text/plain",
        )

        assert isinstance(captured_file_path, BytesIO)
        assert captured_file_path.getvalue() == plaintext

    def test_encrypt_and_store_does_not_write_to_disk(self):
        store = _make_chunk_store(vault_path=Path("/test/vault"))

        def mock_encrypt_file(*, file_path, vault_path, master_key, vault_id, file_id):
            return []

        store.encryption_service.encrypt_file = mock_encrypt_file
        store.file_service.create_file_entry_with_blobs = Mock(return_value=SimpleNamespace(id=1))

        blob_dir = Path("/test/vault/blobs")
        tmp_dir = blob_dir / ".tmp"

        store._encrypt_and_store(
            plaintext=b"test",
            file_id="file_id",
            content_hash="hash",
            mime_type="text/plain",
        )


class TestLoadBlobIndex:
    def test_load_blob_index_stores_index(self):
        from app.infrastructure.fuse.chunk_store.types import ChunkIndex

        store = _make_chunk_store()
        blob_ids = ["blob1.enc", "blob2.enc"]
        store.load_blob_index("file_xyz", blob_ids)

        assert "file_xyz" in store._indices
        assert isinstance(store._indices["file_xyz"], ChunkIndex)
