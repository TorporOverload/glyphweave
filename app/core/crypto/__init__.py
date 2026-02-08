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
from app.core.crypto.service.encryption_service import EncryptionService
from app.core.crypto.service.key_service import KeyService
from app.core.crypto.service.utils import (
    generate_id,
    save_vault_key,
    compute_hash,
    load_vault_key   
)

# Data types
from app.core.crypto.types import KDFParams, KeyPurpose, VaultKeyFile, WrappedKey

__all__ = [
    # Services
    "EncryptionService",
    "KeyService",
    "generate_id",
    'save_vault_key',
    "compute_hash",
    "load_vault_key",
    # Types
    "KDFParams",
    "WrappedKey",
    "VaultKeyFile",
    "KeyPurpose",
]
