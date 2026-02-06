"""Data types and models for the crypto module."""

import base64
from dataclasses import dataclass
from enum import Enum

from app.core.crypto.constants import (
    ARGON2_ITERATIONS,
    ARGON2_LENGTH,
    ARGON2_MEMORY_KB,
    ARGON2_PARALLELISM,
    ARGON2_SALT_SIZE,
)


@dataclass(frozen=True)
class KDFParams:
    """Argon2id key derivation function parameters"""

    algorithm: str = "Argon2id"
    length: int = ARGON2_LENGTH
    memory_kb: int = ARGON2_MEMORY_KB
    iterations: int = ARGON2_ITERATIONS
    parallelism: int = ARGON2_PARALLELISM
    salt_size: int = ARGON2_SALT_SIZE

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "length": self.length,
            "memory_kb": self.memory_kb,
            "iterations": self.iterations,
            "parallelism": self.parallelism,
            "salt_size": self.salt_size,
        }


@dataclass
class WrappedKey:
    """Encrypted master key with wrapping metadata."""

    ciphertext: bytes  # aes_key_wrapped
    salt: bytes
    kdf_params: KDFParams

    def to_dict(self) -> dict:
        return {
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "kdf_params": self.kdf_params.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "WrappedKey":
        return cls(
            ciphertext=base64.b64decode(data["ciphertext"]),
            salt=base64.b64decode(data["salt"]),
            kdf_params=KDFParams(
                algorithm=data["kdf_params"]["algorithm"],
                length=data["kdf_params"]["length"],
                memory_kb=data["kdf_params"]["memory_kb"],
                iterations=data["kdf_params"]["iterations"],
                parallelism=data["kdf_params"]["parallelism"],
                salt_size=data["kdf_params"]["salt_size"],
            ),
        )


@dataclass
class VaultKeyFile:
    """Complete vault.key file structure."""

    password_wrapped: WrappedKey
    recovery_wrapped: WrappedKey
    check_nonce: bytes
    check_value: bytes  # Encrypted CHECK_PLAINTEXT for password verification 
    vault_id: str

    def to_dict(self) -> dict:
        return {
            "vault_id": self.vault_id,
            "password_wrapped": self.password_wrapped.to_dict(),
            "recovery_wrapped": self.recovery_wrapped.to_dict(),
            "check_nonce": base64.b64encode(self.check_nonce).decode("ascii"),
            "check_value": base64.b64encode(self.check_value).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VaultKeyFile":
        return cls(
            vault_id=data["vault_id"],
            password_wrapped=WrappedKey.from_dict(data["password_wrapped"]),
            recovery_wrapped=WrappedKey.from_dict(data["recovery_wrapped"]),
            check_nonce=base64.b64decode(data["check_nonce"]),
            check_value=base64.b64decode(data["check_value"])            
        )

class KeyPurpose(Enum):
    """Purpose-specific key derivation contexts."""

    FILE = "file"
    DATABASE = "database"
    EVENT = "event"
    BACKUP = "backup"
    RECOVERY = "recovery"
