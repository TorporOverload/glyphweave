"""Public crypto package exports.

See `docs/crypto.md` for the full key hierarchy and module reference.
"""

from app.infrastructure.crypto.service.encryption_service import EncryptionService
from app.infrastructure.crypto.primitives.aes_gcm import (
    build_event_aad,
    decrypt_event_bytes,
    encrypt_event_bytes,
)
from app.infrastructure.crypto.service.key_service import KeyService
from app.infrastructure.crypto.service.utils import (
    compute_hash,
    generate_id,
    load_vault_key,
    save_vault_key,
)

from app.infrastructure.crypto.types import (
    KDFParams,
    KeyPurpose,
    VaultKeyFile,
    WrappedKey,
)

__all__ = [
    "EncryptionService",
    "build_event_aad",
    "encrypt_event_bytes",
    "decrypt_event_bytes",
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
