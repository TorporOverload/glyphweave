"""Custom exceptions for the GlyphWeave application."""


class GlyphWeaveError(Exception):
    """Base exception class for all application-specific errors."""

    pass


class CryptoError(GlyphWeaveError):
    """Base exception for cryptography-related errors."""

    pass


class KeyDerivationError(CryptoError):
    """Raised when key derivation fails."""

    pass


class EncryptionError(CryptoError):
    """Raised when encryption fails."""

    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails."""

    pass


class InvalidPasswordError(CryptoError):
    """Raised when the password or recovery key is invalid."""

    pass


class SecureMemoryError(CryptoError):
    """Raised when secure in-memory storage cannot be established."""

    pass
