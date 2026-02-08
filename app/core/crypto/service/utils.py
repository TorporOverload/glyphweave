import json
import uuid
from hashlib import sha256
from pathlib import Path

from app.core.crypto.constants import CHUNK_SIZE
from app.core.crypto.types import VaultKeyFile
from app.utils.logging import logger


def compute_hash(file_path: Path) -> str:
    """Compute the hash of a file."""
    logger.debug(f"Computing SHA-256 hash for file: {file_path}")
    hash = sha256()
    bytes_read = 0
    with open(file_path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            hash.update(chunk)
            bytes_read += len(chunk)
    digest = hash.digest().hex()
    logger.debug(
        f"Hash computed for {file_path}: {digest[:16]}... ({bytes_read} bytes read)"
    )
    return digest


def generate_id() -> str:
    """Ccreates a random id based on uuid4"""
    logger.info("Generating random id")
    rand_id = str(uuid.uuid4())
    logger.debug(f"Generated id: {rand_id}")
    return rand_id


def save_vault_key(vault_key: VaultKeyFile, vault_path: Path):
    """Used to save vault.key file to vault"""
    logger.debug(f"Saving vault key file to: {vault_path}")
    with open(vault_path, "w") as f:
        json.dump(vault_key.to_dict(), f, indent=4)
    logger.debug(f"Vault key file saved successfully to: {vault_path}")


def load_vault_key(vault_path: Path) -> VaultKeyFile:
    """Load vault.key file from vault"""
    logger.debug(f"Loading vault key file from: {vault_path}")
    if not vault_path.exists():
        logger.error(f"Vault key file not found at {vault_path}")
        raise FileNotFoundError(f"Vault key file not found at {vault_path}")
    with open(vault_path, "r") as f:
        data = json.load(f)
    logger.debug(f"Vault key file loaded successfully from: {vault_path}")
    return VaultKeyFile.from_dict(data)
