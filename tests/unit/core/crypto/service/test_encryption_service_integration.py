import pytest
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag

from app.infrastructure.crypto.service import EncryptionService
from app.infrastructure.crypto.constants import (
    BLOB_SIZE_MAX,
    CHUNK_SIZE,
    CHUNKED_MAGIC,
    CHUNKED_VERSION,
    FILE_HEADER_SIZE_BYTES,
)
from app.infrastructure.crypto.primitives.key_derivation import derive_subkey
from app.infrastructure.crypto.primitives.aes_gcm import AESGCMCipher
from app.infrastructure.crypto.types import KeyPurpose
from app.common.paths.vault_layout import resolve_blob_path, writable_blobs_dir


class TestEncryptionServiceStreaming:
    @pytest.fixture
    def service(self):
        return EncryptionService()

    @pytest.fixture
    def master_key(self):
        return b"1" * 32

    @pytest.fixture
    def wrong_key(self):
        return b"2" * 32

    @pytest.fixture
    def vault_id(self):
        return b"vault456"

    @pytest.fixture
    def file_id(self):
        return "file456"

    @pytest.fixture
    def vault_path(self, tmp_path):
        v = tmp_path / "vault"
        v.mkdir()
        return v

    def test_streaming_encrypt_large_file_10mb(
        self, service, tmp_path, vault_path, master_key, vault_id, file_id
    ):
        size = 12 * 1024 * 1024  # 12 MB
        original_data = os.urandom(size)
        input_file = tmp_path / "large.bin"
        input_file.write_bytes(original_data)

        blob_ids = service.encrypt_file(
            input_file, vault_path, master_key, vault_id, file_id
        )

        assert len(blob_ids) >= 2, f"Expected multiple blobs for {size} bytes, got {len(blob_ids)}"

        for blob_id in blob_ids:
            blob_path = resolve_blob_path(vault_path, blob_id)
            assert blob_path.exists()
            assert blob_path.stat().st_size > 0

        output_file = tmp_path / "output.bin"
        service.decrypt_file(
            vault_path, blob_ids, output_file, master_key, vault_id, file_id
        )

        assert output_file.read_bytes() == original_data

    def test_streaming_encrypt_20mb(
        self, service, tmp_path, vault_path, master_key, vault_id, file_id
    ):
        size = 20 * 1024 * 1024
        original_data = os.urandom(size)
        input_file = tmp_path / "very_large.bin"
        input_file.write_bytes(original_data)

        blob_ids = service.encrypt_file(
            input_file, vault_path, master_key, vault_id, file_id
        )

        assert len(blob_ids) >= 2, f"Expected at least 2 blobs for 20MB file, got {len(blob_ids)}"

        output_file = tmp_path / "output.bin"
        service.decrypt_file(
            vault_path, blob_ids, output_file, master_key, vault_id, file_id
        )

        assert output_file.read_bytes() == original_data

    def test_decryption_with_wrong_key_fails(
        self, service, tmp_path, vault_path, master_key, wrong_key, vault_id, file_id
    ):
        original_data = b"Secret message" * 1000
        input_file = tmp_path / "secret.txt"
        input_file.write_bytes(original_data)

        blob_ids = service.encrypt_file(
            input_file, vault_path, master_key, vault_id, file_id
        )

        output_file = tmp_path / "decrypted.txt"
        with pytest.raises(InvalidTag):
            service.decrypt_file(
                vault_path, blob_ids, output_file, wrong_key, vault_id, file_id
            )

    def test_tampered_magic_bytes_detected(
        self, service, tmp_path, vault_path, master_key, vault_id, file_id
    ):
        blob_id = "tampered_magic.enc"

        file_key = derive_subkey(master_key, vault_id, KeyPurpose.FILE, file_id)
        cipher = AESGCMCipher(file_key)

        bad_magic = b"BAD_"
        raw_header = bad_magic + bytes([CHUNKED_VERSION]) + (1).to_bytes(4, "big")
        encrypted_header = cipher.encrypt_header(raw_header, file_id)

        writable_blobs_dir(vault_path).mkdir(parents=True, exist_ok=True)
        resolve_blob_path(vault_path, blob_id).write_bytes(encrypted_header + b"some data")

        output_file = tmp_path / "output.txt"
        with pytest.raises(ValueError, match="Invalid magic"):
            service.decrypt_file(
                vault_path, [blob_id], output_file, master_key, vault_id, file_id
            )

    def test_multi_blob_spanning_chunks(
        self, service, tmp_path, vault_path, master_key, vault_id, file_id
    ):
        # Create file that spans exactly 2 blobs (between 10MB and 20MB)
        size = 15 * 1024 * 1024
        original_data = b"B" * size
        input_file = tmp_path / "spanning.bin"
        input_file.write_bytes(original_data)

        blob_ids = service.encrypt_file(
            input_file, vault_path, master_key, vault_id, file_id
        )

        assert len(blob_ids) == 2, f"Expected 2 blobs, got {len(blob_ids)}"

        # Verify first blob is near max size
        first_blob_path = resolve_blob_path(vault_path, blob_ids[0])
        assert first_blob_path.stat().st_size >= BLOB_SIZE_MAX * 0.9

        # Verify second blob exists and has reasonable size
        second_blob_path = resolve_blob_path(vault_path, blob_ids[1])
        assert second_blob_path.exists()
        assert second_blob_path.stat().st_size > 0
        assert second_blob_path.stat().st_size <= BLOB_SIZE_MAX

        output_file = tmp_path / "output.bin"
        service.decrypt_file(
            vault_path, blob_ids, output_file, master_key, vault_id, file_id
        )

        assert output_file.read_bytes() == original_data

    def test_multi_blob_three_way_split(
        self, service, tmp_path, vault_path, master_key, vault_id, file_id
    ):
        # Create file that spans 3 blobs (between 20MB and 30MB)
        size = 25 * 1024 * 1024
        original_data = os.urandom(size)
        input_file = tmp_path / "triple_blob.bin"
        input_file.write_bytes(original_data)

        blob_ids = service.encrypt_file(
            input_file, vault_path, master_key, vault_id, file_id
        )

        assert len(blob_ids) == 3, f"Expected 3 blobs, got {len(blob_ids)}"

        output_file = tmp_path / "output.bin"
        service.decrypt_file(
            vault_path, blob_ids, output_file, master_key, vault_id, file_id
        )

        assert output_file.read_bytes() == original_data

    def test_streaming_decryption_verifies_data_integrity(
        self, service, tmp_path, vault_path, master_key, vault_id, file_id
    ):
        # Test that decryption works correctly by reading output in chunks
        size = 5 * 1024 * 1024
        original_data = os.urandom(size)
        input_file = tmp_path / "partial_test.bin"
        input_file.write_bytes(original_data)

        blob_ids = service.encrypt_file(
            input_file, vault_path, master_key, vault_id, file_id
        )

        output_file = tmp_path / "output.bin"
        service.decrypt_file(
            vault_path, blob_ids, output_file, master_key, vault_id, file_id
        )

        # Verify by reading in different chunk sizes
        output_data = output_file.read_bytes()
        assert len(output_data) == len(original_data)

        # Verify specific regions
        assert output_data[0:1024] == original_data[0:1024]
        assert output_data[-1024:] == original_data[-1024:]
        mid = len(original_data) // 2
        assert output_data[mid:mid+1024] == original_data[mid:mid+1024]