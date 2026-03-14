"""AES key wrapping and unwrapping operations."""

from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_unwrap_with_padding,
    aes_key_wrap,
    aes_key_wrap_with_padding,
)

from app.core.crypto.types import KeyMaterial
from app.exceptions.crypto import InvalidPasswordError
from app.utils.logging import logger, timed_operation


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
    if not isinstance(key_encryption_key, bytes):
        raise TypeError("Invalid key type")

    if not isinstance(key_to_wrap, bytes):
        raise TypeError("Invalid key type")
        
    if len(key_to_wrap) % 8 == 0:
        wrapped = aes_key_wrap(key_encryption_key, key_to_wrap)
    else:
        wrapped = aes_key_wrap_with_padding(key_encryption_key, key_to_wrap)
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
    
    if not isinstance(key_encryption_key, bytes):
        raise TypeError("Invalid key type")

    if not isinstance(wrapped_key, bytes):
        raise TypeError("Invalid key type")
    
    try:
        key = aes_key_unwrap(key_encryption_key, wrapped_key)
        logger.debug("Key unwrapped successfully.")
        return key
    except InvalidUnwrap:
        try:
            key = aes_key_unwrap_with_padding(key_encryption_key, wrapped_key)
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
