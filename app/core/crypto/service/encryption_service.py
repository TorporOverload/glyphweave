"""Encryption and decryption service for files, file names, and logfiles"""

import math
from pathlib import Path

from app.core.crypto.constants import (
    CHUNK_SIZE,
    CHUNKED_MAGIC,
    CHUNKED_VERSION,
    FILE_HEADER_SIZE_BYTES,
)
from app.core.crypto.primitives.aes_gcm import AESGCMCipher
from app.core.crypto.primitives.key_derivation import derive_subkey
from app.core.crypto.types import KeyPurpose
from app.utils.logging import logger, timed_operation


class EncryptionService:
    @timed_operation("encrypt_file")
    def encrypt_file(
        self,
        file_path: Path,
        vault_path: Path,
        master_key: bytes,
        vault_id: bytes,
        file_id: str,
    ) -> list[str]:
        """
        Encrypt a file and split into chunks/blobs.

        Args:
            file_path: Path to the file to encrypt
            vault_path: Path to vault directory where blobs are stored
            master_key: Master encryption key
            vault_id: Vault identifier for key derivation
            file_id: File identifier for key derivation and AAD

        Returns: List of blob IDs (filenames) created

        Raises:
            FileNotFoundError: If the file doesn't exist
        """
        logger.debug(f"Encrypting file {str(file_path)}.")

        if not file_path.exists() or not file_path.is_file():
            logger.error(f"File {file_path} not found.")
            raise FileNotFoundError(f"File {file_path} not found.")

        file_size = file_path.stat().st_size
        chunk_count = math.ceil(file_size / CHUNK_SIZE)

        # Derive file-specific encryption key
        file_key = derive_subkey(master_key, vault_id, KeyPurpose.FILE, file_id)
        cipher = AESGCMCipher(file_key)

        blobs = []
        current_blob = bytearray()
        blob_target_size = 10 * 1024 * 1024  # 10MB

        chunk_index = 0

        # Header: magic(4) + version(1) + chunk_count(4)
        raw_header = (
            CHUNKED_MAGIC + bytes([CHUNKED_VERSION]) + chunk_count.to_bytes(4, "big")
        )

        encrypted_header = cipher.encrypt_header(raw_header, file_id)

        current_blob.extend(encrypted_header)

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break

                # Check if this is the last chunk
                next_byte = f.read(1)
                is_last_chunk = len(next_byte) == 0
                if next_byte:
                    f.seek(-1, 1)  # put back the byte

                # Encrypt the chunk
                encrypted_data = cipher.encrypt_chunk(
                    chunk, file_id, chunk_index, is_last_chunk
                )

                # Check if adding this chunk exceeds blob size target
                if len(current_blob) + len(encrypted_data) > blob_target_size and len(
                    current_blob
                ) > len(encrypted_header):
                    # Save current blob and start a new one
                    blob_id = self._save_blob(current_blob, vault_path)
                    blobs.append(blob_id)
                    current_blob = bytearray()

                current_blob.extend(encrypted_data)
                chunk_index += 1

        # Save the final blob
        if len(current_blob) > len(encrypted_header):
            blob_id = self._save_blob(current_blob, vault_path)
            blobs.append(blob_id)

        logger.debug(f"File encrypted successfully into {len(blobs)} blob(s).")
        return blobs

    @timed_operation("decrypt_file")
    def decrypt_file(
        self,
        vault_path: Path,
        blob_ids: list[str],
        output_path: Path,
        master_key: bytes,
        vault_id: bytes,
        file_id: str,
    ) -> None:
        """
        Decrypt a file from blobs and write to output path.

        Args:
            vault_path: Path to vault directory containing blobs
            blob_ids: List of blob IDs to decrypt
            output_path: Path where decrypted file will be written
            master_key: Master encryption key
            vault_id: Vault identifier for key derivation
            file_id: File identifier for key derivation and AAD

        Raises:
            FileNotFoundError: If a blob is not found
            ValueError: If blob format is invalid
            Exception: If decryption fails
        """
        logger.debug(f"Decrypting file to {str(output_path)}.")

        # Derive file-specific decryption key
        file_key = derive_subkey(master_key, vault_id, KeyPurpose.FILE, file_id)
        cipher = AESGCMCipher(file_key)

        chunk_index = 0
        chunk_count = 0  # Will be read from header

        with open(output_path, "wb") as outfile:
            for i, blob_id in enumerate(blob_ids):
                blob_path = vault_path / blob_id
                if not blob_path.exists():
                    raise FileNotFoundError(f"Blob {blob_id} not found.")

                with open(blob_path, "rb") as f:
                    if i == 0:
                        # Read and decrypt from first blob

                        encrypted_header = f.read(FILE_HEADER_SIZE_BYTES)
                        if len(encrypted_header) != FILE_HEADER_SIZE_BYTES:
                            raise ValueError("Invalid header size")

                        try:
                            plaintext_header = cipher.decrypt_header(
                                encrypted_header, file_id
                            )
                        except ValueError as e:
                            logger.error(
                                f"Failed to decrypt header for file {file_id}: {e}"
                            )
                            raise ValueError("Invalid header") from e

                        # extract details from raw header
                        magic = plaintext_header[:4]
                        if magic != CHUNKED_MAGIC:
                            raise ValueError("Invalid magic bytes in encrypted file")

                        version = plaintext_header[4]
                        if version != CHUNKED_VERSION:
                            logger.error(
                                f"Unsupported chunk version '{version}' for: {file_id}"
                            )
                            raise ValueError(
                                f"Unsupported encryption version: {version}"
                            )

                        chunk_count = int.from_bytes(plaintext_header[5:9], "big")

                    # Process chunks in this blob
                    while chunk_index < chunk_count:
                        is_last_chunk = chunk_index == chunk_count - 1
                        target_size = 0

                        encrypted_data = b""
                        if is_last_chunk:
                            # Read remaining data in blob (last chunk may be smaller)
                            encrypted_data = f.read()
                        else:
                            # Standard chunk size: 12 (nonce) + CHUNK_SIZE + 16 (tag)
                            target_size = 12 + CHUNK_SIZE + 16
                            encrypted_data = f.read(target_size)

                        if not encrypted_data:
                            # End of this blob, move to next
                            break

                        if not is_last_chunk and len(encrypted_data) != target_size:
                            raise ValueError(
                                f"Incomplete chunk data at index {chunk_index}"
                            )

                        # Decrypt the chunk
                        try:
                            plaintext = cipher.decrypt_chunk(
                                encrypted_data, file_id, chunk_index, is_last_chunk
                            )
                        except Exception as e:
                            logger.error(
                                f"Decryption failed for chunk {chunk_index}: {e}"
                            )
                            raise e

                        outfile.write(plaintext)
                        chunk_index += 1

        if chunk_index != chunk_count:
            raise ValueError(
                "Incomplete encrypted file: "
                f"expected {chunk_count} chunk(s), got {chunk_index}"
            )

        logger.debug("File decrypted successfully.")

    @staticmethod
    def _save_blob(blob_data: bytearray, vault_path: Path) -> str:
        """
        Save blob data to vault and return blob ID.

        Args:
            blob_data: The blob data to save
            vault_path: Path to vault directory

        Returns: Blob ID (filename)
        """
        import secrets

        blob_id = secrets.token_hex(16) + ".enc"
        blob_path = vault_path / blob_id
        with open(blob_path, "wb") as blob_file:
            blob_file.write(blob_data)
        return blob_id
