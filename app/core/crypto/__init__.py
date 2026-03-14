"""Public crypto package exports.

See `docs/crypto.md` for the full key hierarchy and module reference.
"""

from app.core.crypto.service.encryption_service import EncryptionService
from app.core.crypto.service.key_service import KeyService
from app.core.crypto.service.utils import (
    compute_hash,
    generate_id,
    load_vault_key,
    save_vault_key,
)

from app.core.crypto.types import KDFParams, KeyPurpose, VaultKeyFile, WrappedKey

__all__ = [
    "EncryptionService",
    "KeyService",
    "generate_id",
    "save_vault_key",
    "compute_hash",
    "load_vault_key",
    "KDFParams",
    "WrappedKey",
    "VaultKeyFile",
    "KeyPurpose",
]
