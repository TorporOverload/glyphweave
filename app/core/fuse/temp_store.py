"""
TempStore - Manages encrypted temporary blob files for WAL entries.

When a chunk is written during FUSE editing, the plaintext is encrypted
and stored in a local runtime blob file
(.glyphweave/vaults/{vault_id}/cache/temp-blobs/{uuid}.enc). The
temp_blob_id is then stored in the WalEntry for crash recovery.

On flush: temp blobs are read, decrypted, and content written to final blobs.
On checkpoint: temp blobs are deleted along with their WalEntry records.

ENCRYPTION:
    Each temp blob is encrypted using the file's derived key (same as
    final blobs), ensuring consistent key management.

FILE FORMAT:
    [12 bytes nonce][ciphertext + 16 bytes GCM tag]

SECURITY:
    - Temp blobs are encrypted at rest (same protection as final blobs)
    - Files are deleted after checkpoint (no lingering plaintext)
    - Uses HKDF-derived keys with file_id context
"""

import os
import secrets
from pathlib import Path
from typing import Optional, Set

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.crypto.constants import NONCE_SIZE
from app.core.crypto.service.key_service import KeyService
from app.core.crypto.types import KeyPurpose
from app.core.runtime_layout import wal_temp_blobs_dir
from app.utils.logging import logger


class TempStore:
    """
    Manages encrypted temporary blob files for WAL entries.

    Temp blobs provide durability for uncommitted writes. Each write
    operation creates a temp blob containing the encrypted chunk data.
    The blob ID is stored in the database (WalEntry.temp_blob_id).

    Usage:
        store = TempStore(cache_dir, key_service)

        # Write a temp blob
        blob_id = store.write_temp_blob(file_id, chunk_index, plaintext_data)

        # Read it back
        data = store.read_temp_blob(file_id, chunk_index, blob_id)

        # Clean up after checkpoint
        store.delete_temp_blob(blob_id)
    """

    def __init__(
        self,
        cache_dir: Path,
        key_service: KeyService,
    ):
        """
        Initialize the temp blob store.

        Args:
            cache_dir: Path to the local runtime cache directory
            key_service: For deriving file-specific encryption keys
        """
        self.cache_dir = Path(cache_dir)
        self.key_service = key_service

        # Temp blob directory
        self.tmp_dir = wal_temp_blobs_dir(self.cache_dir)

        # Key cache to avoid repeated derivation
        self._key_cache: dict[str, bytes] = {}

    def _get_file_key(self, file_id: str) -> bytes:
        """Get or derive the file-specific encryption key."""
        if file_id not in self._key_cache:
            self._key_cache[file_id] = self.key_service.derive_sub_key(
                KeyPurpose.FILE, file_id
            )
        return self._key_cache[file_id]

    def _blob_path(self, blob_id: str) -> Path:
        """Get the filesystem path for a temp blob."""
        return self.tmp_dir / f"{blob_id}.enc"

    def write_temp_blob(self, file_id: str, chunk_index: int, plaintext: bytes) -> str:
        """
        Write an encrypted temp blob for a chunk.

        Creates a new temp blob file containing the encrypted chunk data.
        Returns a unique blob_id that can be used to read or delete the blob.

        Args:
            file_id: File identifier for key derivation
            chunk_index: Chunk index (used as AAD for integrity)
            plaintext: The plaintext chunk data to encrypt

        Returns:
            blob_id: Unique identifier for this temp blob (without .enc suffix)
        """
        # Generate unique blob ID
        blob_id = secrets.token_hex(16)

        # Derive encryption key
        file_key = self._get_file_key(file_id)
        cipher = AESGCM(file_key)

        # Generate nonce
        nonce = secrets.token_bytes(NONCE_SIZE)

        # AAD includes file_id and chunk_index to prevent substitution attacks
        aad = f"TEMP_BLOB:{file_id}:{chunk_index}".encode("utf-8")

        # Encrypt
        ciphertext = cipher.encrypt(nonce, plaintext, aad)

        # Write to file
        blob_path = self._blob_path(blob_id)
        try:
            with open(blob_path, "wb") as f:
                f.write(nonce)
                f.write(ciphertext)
                f.flush()
                os.fsync(f.fileno())

            logger.debug(
                f"Wrote temp blob {blob_id} for {file_id}:chunk{chunk_index} "
                f"({len(plaintext)} bytes)"
            )
            return blob_id

        except Exception as e:
            # Clean up partial write
            if blob_path.exists():
                blob_path.unlink()
            logger.error(f"Failed to write temp blob: {e}")
            raise

    def read_temp_blob(
        self, file_id: str, chunk_index: int, blob_id: str
    ) -> Optional[bytes]:
        """
        Read and decrypt a temp blob.

        Args:
            file_id: File identifier for key derivation
            chunk_index: Chunk index (for AAD verification)
            blob_id: The blob identifier returned by write_temp_blob

        Returns:
            Decrypted plaintext, or None if blob not found
        """
        blob_path = self._blob_path(blob_id)

        if not blob_path.exists():
            logger.warning(f"Temp blob not found: {blob_id}")
            return None

        try:
            with open(blob_path, "rb") as f:
                nonce = f.read(NONCE_SIZE)
                ciphertext = f.read()

            if len(nonce) < NONCE_SIZE:
                logger.error(f"Temp blob {blob_id} is corrupted (short nonce)")
                return None

            # Derive key and decrypt
            file_key = self._get_file_key(file_id)
            cipher = AESGCM(file_key)
            aad = f"TEMP_BLOB:{file_id}:{chunk_index}".encode("utf-8")

            plaintext = cipher.decrypt(nonce, ciphertext, aad)
            return plaintext

        except Exception as e:
            logger.error(f"Failed to read temp blob {blob_id}: {e}")
            raise

    def delete_temp_blob(self, blob_id: str) -> bool:
        """
        Delete a temp blob file.

        Called after checkpoint when the WalEntry is deleted.

        Args:
            blob_id: The blob identifier to delete

        Returns:
            True if deleted successfully, False if not found
        """
        blob_path = self._blob_path(blob_id)

        if not blob_path.exists():
            return False

        try:
            blob_path.unlink()
            logger.debug(f"Deleted temp blob {blob_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to delete temp blob {blob_id}: {e}")
            return False

    def cleanup_orphaned(self, valid_blob_ids: Set[str]) -> int:
        """
        Delete temp blobs not referenced by any WalEntry.

        Called during startup to clean up blobs that may have been
        left behind by a crash before checkpoint completed.

        Args:
            valid_blob_ids: Set of blob_ids that are still referenced
                            in the database (WalEntry.temp_blob_id)

        Returns:
            Number of orphaned blobs deleted
        """
        deleted = 0

        if not self.tmp_dir.exists():
            return 0

        for path in self.tmp_dir.glob("*.enc"):
            # Extract blob_id from filename (remove .enc suffix)
            blob_id = path.stem

            if blob_id not in valid_blob_ids:
                try:
                    path.unlink()
                    deleted += 1
                    logger.debug(f"Cleaned up orphaned temp blob: {blob_id}")
                except Exception as e:
                    logger.warning(f"Failed to clean up {blob_id}: {e}")

        if deleted > 0:
            logger.info(f"Cleaned up {deleted} orphaned temp blob(s)")

        return deleted

    def get_all_blob_ids(self) -> Set[str]:
        """
        Get all temp blob IDs currently on disk.

        Used for orphan detection during recovery.

        Returns:
            Set of blob_ids (without .enc suffix)
        """
        if not self.tmp_dir.exists():
            return set()

        return {path.stem for path in self.tmp_dir.glob("*.enc")}
