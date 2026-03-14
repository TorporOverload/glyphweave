from __future__ import annotations

from pathlib import Path

VAULT_METADATA_FILE = ".glyphweave_vault"
VAULT_KEY_FILE = "vault.key"
BLOBS_DIR = "blobs"
EVENTS_DIR = "events"
DB_DUMPS_DIR = "db_dumps"


def metadata_path(vault_path: Path) -> Path:
    """Return the path to the vault metadata file."""
    return Path(vault_path) / VAULT_METADATA_FILE


def vault_key_path(vault_path: Path) -> Path:
    """Return the path to the vault key file."""
    return Path(vault_path) / VAULT_KEY_FILE


def blobs_dir(vault_path: Path) -> Path:
    """Return the path to the vault blobs directory."""
    return Path(vault_path) / BLOBS_DIR


def writable_blobs_dir(vault_path: Path) -> Path:
    """Return the vault blobs directory, creating it if necessary."""
    path = blobs_dir(vault_path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def resolve_blob_path(vault_path: Path, blob_id: str) -> Path:
    """Return the full filesystem path for a blob given its ID."""
    return blobs_dir(vault_path) / blob_id

def ensure_vault_layout(vault_path: Path) -> None:
    """Create all required vault subdirectories if they do not already exist."""
    root = Path(vault_path)
    root.mkdir(parents=True, exist_ok=True)
    writable_blobs_dir(root)
    (root / EVENTS_DIR).mkdir(parents=True, exist_ok=True)
    (root / DB_DUMPS_DIR).mkdir(parents=True, exist_ok=True)
