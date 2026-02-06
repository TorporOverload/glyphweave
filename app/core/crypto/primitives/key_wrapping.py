"""AES key wrapping and unwrapping operations."""

from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)

from app.exceptions.crypto import InvalidPasswordError
from app.utils.logging import logger, timed_operation


@timed_operation("wrap_key")
def wrap_key(key_encryption_key: bytes, key_to_wrap: bytes) -> bytes:
    """
    Wrap a key using AES Key Wrap.

    Args:
        key_encryption_key: The key encryption key (KEK)
        key_to_wrap: The key to be wrapped

    Returns: Wrapped key ciphertext
    """
    logger.debug("Wrapping key with AES Key Wrap.")
    wrapped = aes_key_wrap(key_encryption_key, key_to_wrap)
    logger.debug("Key wrapped successfully.")
    return wrapped


@timed_operation("unwrap_key")
def unwrap_key(key_encryption_key: bytes, wrapped_key: bytes) -> bytes:
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
    try:
        key = aes_key_unwrap(key_encryption_key, wrapped_key)
        logger.debug("Key unwrapped successfully.")
        return key
    except InvalidUnwrap:
        logger.error(
            "Failed to unwrap key: Invalid key encryption key or corrupted wrapped key."
        )
        raise InvalidPasswordError(
            "Invalid key encryption key or corrupted wrapped key"
        )
