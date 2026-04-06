import json
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.infrastructure.crypto.constants import (
    FILE_HEADER_SIZE_BYTES,
    HEADER_AAD,
    NONCE_SIZE,
)
from app.infrastructure.crypto.primitives.key_derivation import derive_subkey
from app.infrastructure.crypto.primitives.secure_memory import secure_zero
from app.infrastructure.crypto.types import KeyMaterial, KeyPurpose


def build_event_aad(*, event_hash: str, version: int, device_id: str) -> bytes:
    return json.dumps(
        {
            "device_id": device_id,
            "event_hash": event_hash,
            "version": version,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def encrypt_event_bytes(
    *,
    plaintext: bytes,
    event_hash: str,
    device_id: str,
    master_key: KeyMaterial,
    vault_id: bytes,
    version: int,
) -> tuple[bytes, bytes]:
    key = derive_subkey(master_key, vault_id, KeyPurpose.EVENT, event_hash)
    try:
        nonce = secrets.token_bytes(NONCE_SIZE)
        aad = build_event_aad(
            event_hash=event_hash,
            version=version,
            device_id=device_id,
        )
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, plaintext, aad)
        return nonce, ciphertext
    finally:
        secure_zero(key)


def decrypt_event_bytes(
    *,
    nonce: bytes,
    ciphertext: bytes,
    event_hash: str,
    device_id: str,
    master_key: KeyMaterial,
    vault_id: bytes,
    version: int,
) -> bytes:
    key = derive_subkey(master_key, vault_id, KeyPurpose.EVENT, event_hash)
    try:
        aad = build_event_aad(
            event_hash=event_hash,
            version=version,
            device_id=device_id,
        )
        return AESGCM(bytes(key)).decrypt(nonce, ciphertext, aad)
    finally:
        secure_zero(key)


class AESGCMCipher:
    def __init__(self, key: KeyMaterial):
        self.cipher = AESGCM(bytes(key))

    def encrypt_header(self, header_data: bytes, file_id: str) -> bytes:
        """
        Encrypt the file header.
        Output format: nonce (12) + ciphertext (9) + tag (16) = 37 bytes
        """
        # Standard 96-bit nonce for the header
        nonce = secrets.token_bytes(12)

        # Unique AAD for the header so it can't be swapped with chunks
        aad = file_id.encode("utf-8") + HEADER_AAD

        ciphertext = self.cipher.encrypt(nonce, header_data, aad)
        return nonce + ciphertext

    def decrypt_header(self, encrypted_header: bytes, file_id: str) -> bytes:
        """
        Decrypt the file header.
        Expects exactly 37 bytes (12 nonce + 9 data + 16 tag).
        """
        if len(encrypted_header) != FILE_HEADER_SIZE_BYTES:
            raise ValueError("Invalid header length")

        nonce = encrypted_header[:12]
        ciphertext = encrypted_header[12:]
        aad = file_id.encode("utf-8") + HEADER_AAD

        return self.cipher.decrypt(nonce, ciphertext, aad)

    def encrypt_chunk(
        self,
        plaintext: bytes,
        file_id: str,
        chunk_index: int,
        is_last_chunk: bool,
    ) -> bytes:
        """
        Encrypt a chunk of data with AES-GCM.

        Returns: nonce + ciphertext (with tag included)
        """
        # Generate nonce: 8 random bytes + 4 bytes chunk index = 12 bytes total
        nonce = secrets.token_bytes(8) + chunk_index.to_bytes(4, "big")

        # Include chunk index and last-chunk flag in AAD
        # to prevent reordering/truncation
        aad = (
            file_id.encode("utf-8")
            + chunk_index.to_bytes(4, "big")
            + bytes([is_last_chunk])
        )

        encrypted_chunk = self.cipher.encrypt(nonce, plaintext, aad)

        return nonce + encrypted_chunk

    def decrypt_chunk(
        self,
        encrypted_data: bytes,
        file_id: str,
        chunk_index: int,
        is_last_chunk: bool,
    ) -> bytes:
        """
        Decrypt a chunk of data with AES-GCM.

        Args:
            encrypted_data: nonce + ciphertext (with tag included)
            file_id: File identifier for AAD
            chunk_index: Current chunk number
            is_last_chunk: Whether this is the last chunk

        Returns: plaintext
        """
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        aad = (
            file_id.encode("utf-8")
            + chunk_index.to_bytes(4, "big")
            + bytes([is_last_chunk])
        )

        plaintext = self.cipher.decrypt(nonce, ciphertext, aad)
        return plaintext
