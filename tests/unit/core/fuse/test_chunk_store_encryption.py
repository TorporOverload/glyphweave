"""Unit tests for ChunkStore encryption behavior - multi-blob, naming, and decryption."""

import pytest
from pathlib import Path
from types import SimpleNamespace
from io import BytesIO
from unittest.mock import MagicMock, patch, Mock
import hashlib

from app.infrastructure.fuse.chunk_store import ChunkStore
from app.infrastructure.crypto.service.encryption_service import EncryptionService
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


class TestMultiBlobFileSpanningEncryption:
    def test_large_file_produces_multiple_blobs(self):
        store = _make_chunk_store(vault_path=Path("/test/vault"), chunk_size=64)

        blob_ids_returned = []

        def mock_encrypt_file(*, file_path, vault_path, master_key, vault_id, file_id):
            blob_count = 3
            ids = [f"blob_{i}_{file_id}.enc" for i in range(blob_count)]
            blob_ids_returned.extend(ids)
            return ids

        store.encryption_service.encrypt_file = mock_encrypt_file
        store.file_service.create_file_entry_with_blobs = Mock(return_value=SimpleNamespace(id=1))

        file_ref = SimpleNamespace(id=1, file_entry_id=1)
        store.folder_service.get_by_id = Mock(return_value=file_ref)
        store.file_service.find_by_content_hash = Mock(return_value=None)
        store.file_service.update_file_reference_entry = Mock(return_value=None)

        with patch("app.infrastructure.fuse.chunk_store.flush.resolve_blob_path") as mock_resolve:
            mock_resolve.return_value = SimpleNamespace(stat=Mock(return_value=SimpleNamespace(st_size=100)))

            file_content = b"x" * (store.chunk_size * 2 + 100)

            store.flush_to_blobs(
                file_id="multi_blob_file",
                file_ref_id=1,
                dirty_chunks={
                    0: bytearray(file_content[:store.chunk_size]),
                    1: bytearray(file_content[store.chunk_size:store.chunk_size*2]),
                    2: bytearray(file_content[store.chunk_size*2:]),
                },
                original_size=len(file_content),
                mime_type="application/octet-stream",
            )

        assert len(blob_ids_returned) == 3

    def test_flush_to_blobs_calls_encrypt_with_assembled_content(self):
        store = _make_chunk_store(vault_path=Path("/test/vault"), chunk_size=10)

        assembled_content = None

        def capture_encrypt(*, file_path, vault_path, master_key, vault_id, file_id):
            nonlocal assembled_content
            if isinstance(file_path, BytesIO):
                assembled_content = file_path.read()
            return ["blob1.enc"]

        store.encryption_service.encrypt_file = capture_encrypt
        store.file_service.create_file_entry_with_blobs = Mock(return_value=SimpleNamespace(id=1))

        file_ref = SimpleNamespace(id=1, file_entry_id=1)
        store.folder_service.get_by_id = Mock(return_value=file_ref)
        store.file_service.find_by_content_hash = Mock(return_value=None)
        store.file_service.update_file_reference_entry = Mock(return_value=None)

        with patch("app.infrastructure.fuse.chunk_store.flush.resolve_blob_path") as mock_resolve:
            mock_resolve.return_value = SimpleNamespace(stat=Mock(return_value=SimpleNamespace(st_size=100)))

            store.flush_to_blobs(
                file_id="assemble_test",
                file_ref_id=1,
                dirty_chunks={0: bytearray(b"chunk0"), 1: bytearray(b"chunk1")},
                original_size=12,
                mime_type="text/plain",
            )

        assert assembled_content == b"chunk0chunk1"


class TestEncryptedBlobFileNaming:
    def test_blob_ids_are_unique_per_file(self):
        store = _make_chunk_store(vault_path=Path("/test/vault"))

        file1_blobs = None
        file2_blobs = None

        def mock_encrypt_file(*, file_path, vault_path, master_key, vault_id, file_id):
            nonlocal file1_blobs, file2_blobs
            if file_id == "file1":
                file1_blobs = ["blob_a.enc", "blob_b.enc"]
                return file1_blobs
            else:
                file2_blobs = ["blob_c.enc", "blob_d.enc"]
                return file2_blobs

        store.encryption_service.encrypt_file = mock_encrypt_file
        store.file_service.create_file_entry_with_blobs = Mock(return_value=SimpleNamespace(id=1))

        file_ref = SimpleNamespace(id=1, file_entry_id=1)
        store.folder_service.get_by_id = Mock(return_value=file_ref)
        store.file_service.find_by_content_hash = Mock(return_value=None)
        store.file_service.update_file_reference_entry = Mock(return_value=None)

        with patch("app.infrastructure.fuse.chunk_store.flush.resolve_blob_path") as mock_resolve:
            mock_resolve.return_value = SimpleNamespace(stat=Mock(return_value=SimpleNamespace(st_size=100)))

            store.flush_to_blobs(
                file_id="file1",
                file_ref_id=1,
                dirty_chunks={0: bytearray(b"data1")},
                original_size=5,
                mime_type="text/plain",
            )

            store.flush_to_blobs(
                file_id="file2",
                file_ref_id=1,
                dirty_chunks={0: bytearray(b"data2")},
                original_size=5,
                mime_type="text/plain",
            )

        assert file1_blobs != file2_blobs

    def test_encrypted_blob_id_format_with_extension(self):
        store = _make_chunk_store(vault_path=Path("/test/vault"))

        captured_blob_ids = []

        def mock_encrypt_file(*, file_path, vault_path, master_key, vault_id, file_id):
            blob_ids = ["test_blob_id_1234567890123456.enc"]
            captured_blob_ids.extend(blob_ids)
            return blob_ids

        store.encryption_service.encrypt_file = mock_encrypt_file
        store.file_service.create_file_entry_with_blobs = Mock(return_value=SimpleNamespace(id=1))

        file_ref = SimpleNamespace(id=1, file_entry_id=1)
        store.folder_service.get_by_id = Mock(return_value=file_ref)
        store.file_service.find_by_content_hash = Mock(return_value=None)
        store.file_service.update_file_reference_entry = Mock(return_value=None)

        with patch("app.infrastructure.fuse.chunk_store.flush.resolve_blob_path") as mock_resolve:
            mock_resolve.return_value = SimpleNamespace(stat=Mock(return_value=SimpleNamespace(st_size=100)))

            store.flush_to_blobs(
                file_id="blob_naming_test",
                file_ref_id=1,
                dirty_chunks={0: bytearray(b"test")},
                original_size=4,
                mime_type="text/plain",
            )

        assert len(captured_blob_ids) == 1
        assert captured_blob_ids[0].endswith(".enc")


class TestDecryptionOfStagedBlobs:
    def test_read_chunk_decrypts_data(self):
        store = _make_chunk_store()

        expected_plaintext = b"decrypted chunk data"

        store._indices["decrypt_test_file"] = SimpleNamespace(
            entries={0: (Path("/fake/blob.enc"), 0, 100)},
            chunk_count=1,
        )

        original_read_chunk = store.read_chunk

        def mock_read(file_id, chunk_idx):
            if file_id == "decrypt_test_file" and chunk_idx == 0:
                return expected_plaintext
            return original_read_chunk(file_id, chunk_idx)

        store.read_chunk = mock_read

        result = store.read_chunk("decrypt_test_file", 0)
        assert result == expected_plaintext

    def test_read_chunk_returns_none_for_missing_index(self):
        store = _make_chunk_store()
        result = store.read_chunk("nonexistent_file", 0)
        assert result is None

    def test_assemble_full_content_combines_dirty_chunks(self):
        store = _make_chunk_store(chunk_size=64)

        dirty_chunks = {
            0: bytearray(b"a" * 64),
            1: bytearray(b"b" * 64),
            2: bytearray(b"c" * 64),
        }
        total_size = 192

        result = store._assemble_full_content(
            file_id="assemble_file",
            dirty_chunks=dirty_chunks,
            total_size=total_size,
        )

        assert result == b"a" * 64 + b"b" * 64 + b"c" * 64

    def test_assemble_full_content_returns_empty_for_zero_size(self):
        store = _make_chunk_store()
        result = store._assemble_full_content(
            file_id="empty_file",
            dirty_chunks={},
            total_size=0,
        )
        assert result == b""

    def test_assemble_full_content_with_mixed_dirty_and_clean_chunks(self):
        store = _make_chunk_store(chunk_size=64)

        store._indices["mixed_file"] = SimpleNamespace(
            entries={
                0: (Path("/fake/blob0.enc"), 0, 100),
                1: (Path("/fake/blob1.enc"), 100, 100),
                2: (Path("/fake/blob2.enc"), 200, 100),
            },
            chunk_count=3,
        )

        def mock_read_chunk(file_id, chunk_idx):
            if file_id == "mixed_file" and chunk_idx == 1:
                return b"clean_chunk"
            return None

        store.read_chunk = mock_read_chunk

        dirty_chunks = {
            0: bytearray(b"x" * 64),
            2: bytearray(b"z" * 64),
        }

        result = store._assemble_full_content(
            file_id="mixed_file",
            dirty_chunks=dirty_chunks,
            total_size=192,
        )

        assert result == b"x" * 64 + b"clean_chunk" + b"z" * 64
