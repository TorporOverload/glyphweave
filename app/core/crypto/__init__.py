"""
Glyphweave Cryptographic Module

A modular cryptographic system with:
- Secure key generation and management (KeyService)
- File encryption/decryption (EncryptionService)
- Recovery phrase management (RecoveryService)
- Low-level primitives (aes_gcm, key_wrapping, key_derivation)
- Secure memory handling utilities
"""

# High-level service
# Utilities
from app.core.crypto.services.encryption_service import EncryptionService
from app.core.crypto.services.key_service import KeyService
from app.core.crypto.services.recovery_service import RecoveryService

# Data types
from app.core.crypto.types import KDFParams, KeyPurpose, VaultKeyFile, WrappedKey

__all__ = [
    # Services
    "EncryptionService",
    "KeyService",
    "RecoveryService",
    # Types
    "KDFParams",
    "WrappedKey",
    "VaultKeyFile",
    "KeyPurpose",
]
