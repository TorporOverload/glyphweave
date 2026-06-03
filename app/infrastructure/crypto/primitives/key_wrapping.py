"""AES key wrapping and unwrapping operations."""

from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)

from app.infrastructure.crypto.types import KeyMaterial
from app.common.exceptions.crypto import InvalidPasswordError
from app.common.logging import logger, timed_operation


def _key_to_bytes(value: KeyMaterial) -> bytes:
    """Normalize supported key material inputs to immutable bytes."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)

@timed_operation("wrap_key")
def wrap_key(key_encryption_key: KeyMaterial, key_to_wrap: KeyMaterial) -> bytes:
    """
    Wrap a key using AES Key Wrap.

    Args:
        key_encryption_key: The key encryption key (KEK)
        key_to_wrap: The key to be wrapped

    Returns: Wrapped key ciphertext
    """
    logger.debug("Wrapping key with AES Key Wrap.")
    normalized_kek = _key_to_bytes(key_encryption_key)
    normalized_key = _key_to_bytes(key_to_wrap)
    wrapped = aes_key_wrap(normalized_kek, normalized_key)
    logger.debug("Key wrapped successfully.")
    return wrapped


@timed_operation("unwrap_key")
def unwrap_key(key_encryption_key: KeyMaterial, wrapped_key: KeyMaterial) -> bytes:
    """
    Unwrap a key using AES Key Wrap.

    Args:
        key_encryption_key: The key encryption key (KEK)
        wrapped_key: The wrapped key ciphertext

    Returns: Unwrapped key plaintext

    Raises:
        InvalidPasswordError: If the key cannot be unwrapped (invalid KEK)
    """
    logger.debug("Unwrapping key with AES Key Wrap.")

    normalized_kek = _key_to_bytes(key_encryption_key)
    normalized_wrapped_key = _key_to_bytes(wrapped_key)

    try:
        key = aes_key_unwrap(normalized_kek, normalized_wrapped_key)
        logger.debug("Key unwrapped successfully.")
        return key
    except InvalidUnwrap:
        logger.error(
            "Failed to unwrap key:"
            " Invalid key encryption key or corrupted wrapped key."
        )
        raise InvalidPasswordError(
            "Invalid key encryption key or corrupted wrapped key"
        )

