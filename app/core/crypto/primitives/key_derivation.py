"""Key derivation primitives using Argon2id and HKDF."""

import secrets

from cryptography.exceptions import AlreadyFinalized
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import argon2, hkdf

from app.core.crypto.constants import (
    HKDF_INFO_BACKUP,
    HKDF_INFO_DATABASE,
    HKDF_INFO_EVENT,
    HKDF_INFO_FILE,
    HKDF_INFO_RECOVERY,
)
from app.core.crypto.types import KDFParams, KeyMaterial, KeyPurpose
from app.exceptions.crypto import KeyDerivationError
from app.utils.logging import logger, timed_operation

# Mapping of key purposes to HKDF info strings for domain separation
HKDF_INFO_MAP = {
    KeyPurpose.FILE: HKDF_INFO_FILE,
    KeyPurpose.DATABASE: HKDF_INFO_DATABASE,
    KeyPurpose.EVENT: HKDF_INFO_EVENT,
    KeyPurpose.BACKUP: HKDF_INFO_BACKUP,
    KeyPurpose.RECOVERY: HKDF_INFO_RECOVERY,
}


@timed_operation("derive_kek_from_password")
def derive_kek_from_password(
    password: str, kdf_params: KDFParams, salt: bytes | None = None
) -> tuple[bytes, bytes]:
    """
    Derive a Key Encryption Key (KEK) from a password using Argon2id.

    Args:
        password: User password
        kdf_params: Argon2id parameters
        salt: Optional salt bytes (generates new if None)

    Returns: Tuple of (derived_key, salt)

    Raises:
        KeyDerivationError: If derivation fails
    """
    logger.debug(f"Deriving key from password with algorithm: {kdf_params.algorithm}.")
    if salt is None:
        salt = secrets.token_bytes(kdf_params.salt_size)

    kdf = argon2.Argon2id(
        salt=salt,
        length=kdf_params.length,
        iterations=kdf_params.iterations,
        lanes=kdf_params.parallelism,
        memory_cost=kdf_params.memory_kb,
    )
    try:
        key = kdf.derive(password.encode("utf-8"))
        logger.debug("Key derived successfully from password.")
        return key, salt
    except (AlreadyFinalized, ValueError) as e:
        logger.error(f"Key derivation failed: {e}")
        raise KeyDerivationError(f"Key derivation failed: {e}") from e


@timed_operation("derive_subkey")
def derive_subkey(
    master_key: KeyMaterial, vault_id: bytes, purpose: KeyPurpose, context: str
) -> bytes:
    """
    Derive a purpose-specific subkey from a master key using HKDF.

    Args:
        master_key: The master key
        vault_id: Vault identifier (used as salt)
        purpose: The purpose of the derived key (file, database, etc.)
        context: Context string (e.g., file_id) for domain separation

    Returns: Derived subkey (32 bytes)

    Raises:
        ValueError: If purpose is not supported
    """
    logger.debug(f"Deriving subkey for {purpose.value}.")

    if purpose not in HKDF_INFO_MAP:
        raise ValueError(f"Unsupported key purpose: {purpose}")

    info = HKDF_INFO_MAP[purpose] + context.encode("utf-8")

    hkdf_instance = hkdf.HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=vault_id,
        info=info,
    )

    return hkdf_instance.derive(master_key)
