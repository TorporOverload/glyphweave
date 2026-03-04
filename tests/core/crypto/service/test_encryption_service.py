import pytest
import os
from pathlib import Path

from app.core.crypto.service import EncryptionService
from app.core.crypto.constants import (
    CHUNK_SIZE,
    CHUNKED_VERSION,
    FILE_HEADER_SIZE_BYTES,
)
from app.core.crypto.primitives.aes_gcm import AESGCMCipher
from app.core.crypto.types import KeyPurpose
from app.core.crypto.primitives.key_derivation import derive_subkey


class TestEncryptionService:
    @pytest.fixture
    def service(self):
        return EncryptionService()

    @pytest.fixture
    def master_key(self):
        return b"0" * 32  # 32 bytes master key

    @pytest.fixture
    def vault_id(self):
        return b"vault123"

    @pytest.fixture
    def file_id(self):
        return "file123"

    @pytest.fixture
    def vault_path(self, tmp_path):
        v = tmp_path / "vault"
        v.mkdir()
        return v

    def test_encrypt_file_not_found(
        self, service, vault_path, master_key, vault_id, file_id
    ):
        with pytest.raises(FileNotFoundError):
            service.encrypt_file(
                Path("non_existent_file"), vault_path, master_key, vault_id, file_id
            )

    def test_encrypt_decrypt_small_file(
        self, service, tmp_path, vault_path, master_key, vault_id, file_id
    ):
        # Create a small file
        original_data = b"Hello World"
        input_file = tmp_path / "input.txt"
        input_file.write_bytes(original_data)

        # Encrypt
        blob_ids = service.encrypt_file(
            input_file, vault_path, master_key, vault_id, file_id
        )
        assert len(blob_ids) == 1

        # Verify blob exists
        assert (vault_path / blob_ids[0]).exists()

        # Decrypt
        output_file = tmp_path / "output.txt"
        service.decrypt_file(
            vault_path, blob_ids, output_file, master_key, vault_id, file_id
        )

        assert output_file.read_bytes() == original_data

    def test_encrypt_decrypt_large_file(
        self, service, tmp_path, vault_path, master_key, vault_id, file_id
    ):
        # Create file larger than chunk size but smaller than blob size (10MB)
        size = 1024 * 1024  # 1MB
        original_data = os.urandom(size)
        input_file = tmp_path / "large_input.bin"
        input_file.write_bytes(original_data)

        blob_ids = service.encrypt_file(
            input_file, vault_path, master_key, vault_id, file_id
        )
        assert len(blob_ids) == 1

        output_file = tmp_path / "large_output.bin"
        service.decrypt_file(
            vault_path, blob_ids, output_file, master_key, vault_id, file_id
        )

        assert output_file.read_bytes() == original_data

    def test_encrypt_decrypt_multi_blob(
        self, service, tmp_path, vault_path, master_key, vault_id, file_id
    ):
        # To trigger multi-blob, we need > 10MB file.
        size = 11 * 1024 * 1024  # 11MB
        # Optimization: use repeatable pattern instead of urandom for speed
        original_data = b"A" * size
        input_file = tmp_path / "huge_input.bin"
        input_file.write_bytes(original_data)

        blob_ids = service.encrypt_file(
            input_file, vault_path, master_key, vault_id, file_id
        )
        assert len(blob_ids) >= 2

        output_file = tmp_path / "huge_output.bin"
        service.decrypt_file(
            vault_path, blob_ids, output_file, master_key, vault_id, file_id
        )

        assert output_file.read_bytes() == original_data

    def test_decrypt_invalid_magic(
        self, service, tmp_path, vault_path, master_key, vault_id, file_id
    ):
        # Create a blob with valid encryption but invalid magic in the header
        blob_id = "bad_magic.enc"

        # Manually encrypt a header with bad magic
        file_key = derive_subkey(master_key, vault_id, KeyPurpose.FILE, file_id)
        cipher = AESGCMCipher(file_key)

        # Header: magic(4) + version(1) + chunk_count(4)
        bad_magic = b"BAD_"
        raw_header = bad_magic + bytes([CHUNKED_VERSION]) + (1).to_bytes(4, "big")

        encrypted_header = cipher.encrypt_header(raw_header, file_id)

        # Write blob
        (vault_path / blob_id).write_bytes(encrypted_header + b"some data")

        with pytest.raises(ValueError, match="Invalid magic bytes"):
            service.decrypt_file(
                vault_path, [blob_id], tmp_path / "out", master_key, vault_id, file_id
            )

    def test_decrypt_tampered_chunk(
        self, service, tmp_path, vault_path, master_key, vault_id, file_id
    ):
        data = b"Secret Data"
        input_file = tmp_path / "input.txt"
        input_file.write_bytes(data)
        blob_ids = service.encrypt_file(
            input_file, vault_path, master_key, vault_id, file_id
        )

        blob_path = vault_path / blob_ids[0]
        blob_data = bytearray(blob_path.read_bytes())

        # Tamper with the last byte of the encrypted data
        blob_data[-1] ^= 0xFF
        blob_path.write_bytes(blob_data)

        # Should fail authentication
        with pytest.raises(Exception):
            service.decrypt_file(
                vault_path, blob_ids, tmp_path / "out", master_key, vault_id, file_id
            )

    def test_decrypt_missing_blob(
        self, service, tmp_path, vault_path, master_key, vault_id, file_id
    ):
        with pytest.raises(FileNotFoundError):
            service.decrypt_file(
                vault_path,
                ["missing_blob.enc"],
                tmp_path / "out",
                master_key,
                vault_id,
                file_id,
            )

    def test_decrypt_incomplete_chunk_stream(
        self, service, tmp_path, vault_path, master_key, vault_id, file_id
    ):
        data = os.urandom(CHUNK_SIZE + 10)
        input_file = tmp_path / "input.bin"
        input_file.write_bytes(data)

        blob_ids = service.encrypt_file(
            input_file, vault_path, master_key, vault_id, file_id
        )
        assert len(blob_ids) == 1

        blob_path = vault_path / blob_ids[0]
        blob_data = blob_path.read_bytes()

        first_chunk_size = 12 + CHUNK_SIZE + 16
        truncated = blob_data[: FILE_HEADER_SIZE_BYTES + first_chunk_size]
        blob_path.write_bytes(truncated)

        with pytest.raises(ValueError, match="Incomplete encrypted file"):
            service.decrypt_file(
                vault_path, blob_ids, tmp_path / "out", master_key, vault_id, file_id
            )
