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
    safe_id = Path(blob_id).name
    if safe_id != blob_id:
        raise ValueError("Invalid blob_id")
    base_dir = blobs_dir(vault_path).resolve()
    resolved = (base_dir / safe_id).resolve()
    if not resolved.is_relative_to(base_dir):
        raise ValueError("Blob path escapes vault directory")
    return resolved

def create_vault_layout(vault_path: Path) -> None:
    """Create all required vault subdirectories if they do not already exist."""
    root = Path(vault_path)
    root.mkdir(parents=True, exist_ok=True)
    writable_blobs_dir(root)
    (root / EVENTS_DIR).mkdir(parents=True, exist_ok=True)
    (root / DB_DUMPS_DIR).mkdir(parents=True, exist_ok=True)
