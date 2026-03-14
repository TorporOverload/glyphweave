from __future__ import annotations

from pathlib import Path

from app.config import VAULTS_DIR

CACHE_DIR = "cache"
FUSE_MOUNTS_DIR = "fuse-mounts"
WAL_TEMP_BLOBS_DIR = "temp-blobs"
DECRYPTED_FILES_DIR = "decrypted-files"
PLAINTEXT_STAGING_DIR = ".tmp"


def local_data_path_for(app_data_dir: Path, vault_id: str) -> Path:
    """Return the local data directory path for the given vault ID."""
    return Path(app_data_dir) / VAULTS_DIR / vault_id


def runtime_cache_dir(local_data_path: Path) -> Path:
    """Return the runtime cache directory path within the local data directory."""
    return Path(local_data_path) / CACHE_DIR


def fuse_mounts_dir(cache_dir: Path) -> Path:
    """Return the FUSE mount points directory, creating it if necessary."""
    path = Path(cache_dir) / FUSE_MOUNTS_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def wal_temp_blobs_dir(cache_dir: Path) -> Path:
    """Return the temporary WAL blob staging directory, creating it if necessary."""
    path = Path(cache_dir) / WAL_TEMP_BLOBS_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def decrypted_files_dir(cache_dir: Path) -> Path:
    """Return the decrypted files cache directory, creating it if necessary."""
    path = Path(cache_dir) / DECRYPTED_FILES_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def plaintext_staging_dir(cache_dir: Path) -> Path:
    """Return the plaintext staging directory used during write operations, creating it
    if necessary."""
    path = Path(cache_dir) / PLAINTEXT_STAGING_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path
