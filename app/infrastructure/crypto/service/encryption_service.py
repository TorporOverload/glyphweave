"""Encryption and decryption service for files, file names, and logfiles"""

import math
from pathlib import Path
from typing import BinaryIO

from app.common.logging import logger, timed_operation
from app.common.paths.vault_layout import resolve_blob_path, writable_blobs_dir
from app.infrastructure.crypto.constants import (
    BLOB_SIZE_MAX,
    CHUNK_SIZE,
    CHUNKED_MAGIC,
    CHUNKED_VERSION,
    FILE_HEADER_SIZE_BYTES,
)
from app.infrastructure.crypto.primitives.aes_gcm import AESGCMCipher
from app.infrastructure.crypto.primitives.key_derivation import derive_subkey
from app.infrastructure.crypto.primitives.secure_memory import secure_zero
from app.infrastructure.crypto.types import KeyMaterial, KeyPurpose


class EncryptionService:
    @timed_operation("encrypt_file")
    def encrypt_file(
        self,
        file_path: Path | BinaryIO,
        vault_path: Path,
        master_key: KeyMaterial,
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

        blob_store = writable_blobs_dir(vault_path)
        source_handle: BinaryIO
        file_size: int | None
        close_after = False
        if isinstance(file_path, Path):
            if not file_path.exists() or not file_path.is_file():
                logger.error(f"File {file_path} not found.")
                raise FileNotFoundError(f"File {file_path} not found.")
            file_size = file_path.stat().st_size
            source_handle = open(file_path, "rb")
            close_after = True
        else:
            file_size = None
            source_handle = file_path

        try:
            if file_size is None:
                file_size = self._stream_size(source_handle)
            chunk_count = math.ceil(file_size / CHUNK_SIZE)
            file_key = derive_subkey(master_key, vault_id, KeyPurpose.FILE, file_id)
            blobs: list[str] = []
            try:
                cipher = AESGCMCipher(file_key)
                current_blob = bytearray()
                blob_target_size = BLOB_SIZE_MAX
                chunk_index = 0

                raw_header = (
                    CHUNKED_MAGIC
                    + bytes([CHUNKED_VERSION])
                    + chunk_count.to_bytes(4, "big")
                )
                encrypted_header = cipher.encrypt_header(raw_header, file_id)
                current_blob.extend(encrypted_header)

                while True:
                    chunk = source_handle.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    next_byte = source_handle.read(1)
                    is_last_chunk = len(next_byte) == 0
                    if next_byte:
                        source_handle.seek(-1, 1)

                    encrypted_data = cipher.encrypt_chunk(
                        chunk,
                        file_id,
                        chunk_index,
                        is_last_chunk,
                    )
                    if len(current_blob) + len(
                        encrypted_data
                    ) > blob_target_size and len(current_blob) > len(encrypted_header):
                        blob_id = self._save_blob(current_blob, blob_store)
                        blobs.append(blob_id)
                        current_blob = bytearray()

                    current_blob.extend(encrypted_data)
                    chunk_index += 1

                if len(current_blob) > len(encrypted_header):
                    blob_id = self._save_blob(current_blob, blob_store)
                    blobs.append(blob_id)

                logger.debug(f"File encrypted successfully into {len(blobs)} blob(s).")
                return blobs
            except Exception:
                for blob_id in blobs:
                    (blob_store / blob_id).unlink(missing_ok=True)
                raise
            finally:
                secure_zero(file_key)
        finally:
            if close_after:
                source_handle.close()

    @timed_operation("decrypt_file")
    def decrypt_file(
        self,
        vault_path: Path,
        blob_ids: list[str],
        output_path: Path,
        master_key: KeyMaterial,
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
        tmp_output = output_path.with_suffix(output_path.suffix + ".tmp")

        try:
            chunk_index = 0
            chunk_count = 0

            with open(tmp_output, "wb") as outfile:
                for i, blob_id in enumerate(blob_ids):
                    blob_path = resolve_blob_path(vault_path, blob_id)
                    if not blob_path.exists():
                        raise FileNotFoundError(f"Blob {blob_id} not found.")

                    with open(blob_path, "rb") as f:
                        if i == 0:
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

                            magic = plaintext_header[:4]
                            if magic != CHUNKED_MAGIC:
                                raise ValueError(
                                    "Invalid magic bytes in encrypted file"
                                )

                            version = plaintext_header[4]
                            if version != CHUNKED_VERSION:
                                logger.error(
                                    "Unsupported chunk version '%s' for: %s",
                                    version,
                                    file_id,
                                )
                                raise ValueError(
                                    f"Unsupported encryption version: {version}"
                                )

                            chunk_count = int.from_bytes(plaintext_header[5:9], "big")

                        while chunk_index < chunk_count:
                            is_last_chunk = chunk_index == chunk_count - 1
                            target_size = 0

                            encrypted_data = b""
                            if is_last_chunk:
                                encrypted_data = f.read()
                            else:
                                target_size = 12 + CHUNK_SIZE + 16
                                encrypted_data = f.read(target_size)

                            if not encrypted_data:
                                break

                            if not is_last_chunk and len(encrypted_data) != target_size:
                                raise ValueError(
                                    f"Incomplete chunk data at index {chunk_index}"
                                )

                            try:
                                plaintext = cipher.decrypt_chunk(
                                    encrypted_data, file_id, chunk_index, is_last_chunk
                                )
                            except Exception as e:
                                logger.error(
                                    f"Decryption failed for chunk {chunk_index}: {e}"
                                )
                                raise

                            outfile.write(plaintext)
                            chunk_index += 1

            if chunk_index != chunk_count:
                raise ValueError(
                    "Incomplete encrypted file: "
                    f"expected {chunk_count} chunk(s), got {chunk_index}"
                )

            tmp_output.replace(output_path)
            logger.debug("File decrypted successfully.")
        except Exception:
            tmp_output.unlink(missing_ok=True)
            raise
        finally:
            secure_zero(file_key)

    @staticmethod
    def _save_blob(blob_data: bytearray, blob_store: Path) -> str:
        """
        Save blob data to vault and return blob ID.

        Args:
            blob_data: The blob data to save
            blob_store: Path to blob directory

        Returns: Blob ID (filename)
        """
        import secrets

        blob_id = secrets.token_hex(16) + ".enc"
        blob_path = blob_store / blob_id
        with open(blob_path, "wb") as blob_file:
            blob_file.write(blob_data)
        return blob_id

    @staticmethod
    def _stream_size(handle: BinaryIO) -> int:
        """Return the total size of a seekable binary stream in bytes.

        The current stream position is preserved: the cursor is temporarily moved
        to the end of the stream to determine its size, then restored to its
        original position.

        args:
            handle : BinaryIO
            A seekable binary stream object that supports tell() and seek().

        Returns:
            int
            The size of the stream in bytes.

        Raises:
            ValueError
                If the provided stream does not support seeking or raises an
                AttributeError or OSError when tell() or seek() are used.
        """
        try:
            seekable = getattr(handle, "seekable", None)
            if callable(seekable) and not seekable():
                raise ValueError(
                    "encrypt_file requires a seekable binary input stream"
                )
            current = handle.tell()
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(current)
            return size
        except (AttributeError, OSError):
            raise ValueError("encrypt_file requires a seekable binary input stream")
