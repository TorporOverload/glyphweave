from __future__ import annotations

import time
from pathlib import Path

from app.common.logging import logger
from app.common.paths.runtime_layout import (
    decrypted_files_dir,
    fuse_mounts_dir,
    local_data_path_for,
    plaintext_staging_dir,
    runtime_cache_dir,
    wal_temp_blobs_dir,
)
from app.infrastructure.crypto.service.key_service import KeyService
from app.infrastructure.persistence.registry_service import read_vault_metadata
from app.services.models import VaultContext


def ensure_local_runtime_dirs(local_data_path: Path) -> None:
    """Create all required local runtime cache subdirectories for a vault."""
    local_data_path.mkdir(parents=True, exist_ok=True)
    cache_dir = runtime_cache_dir(local_data_path)
    cache_dir.mkdir(parents=True, exist_ok=True)
    fuse_mounts_dir(cache_dir)
    wal_temp_blobs_dir(cache_dir)
    decrypted_files_dir(cache_dir)
    plaintext_staging_dir(cache_dir)


def assign_vault_location(
    context: VaultContext,
    *,
    vault_path: Path,
    vault_id: str,
    vault_name: str,
) -> None:
    """Set vault path, ID, name, and local data path on the context."""
    context.vault_path = vault_path
    context.vault_id = vault_id
    context.vault_name = vault_name
    context.local_data_path = local_data_path_for(context.app_data_dir, vault_id)


def prepare_existing_vault_context(
    context: VaultContext,
    vault_path: Path,
    fallback_alias: str | None = None,
    fallback_vault_id: str | None = None,
) -> None:
    """Read vault metadata from disk and populate the context with location details."""
    start = time.time()
    t1 = time.time()
    if not vault_path.exists() or not vault_path.is_dir():
        raise FileNotFoundError(f"Vault path not found: {vault_path}")
    logger.debug(f"vault_path.exists/is_dir check took {time.time() - t1:.2f}s")

    t2 = time.time()
    metadata = read_vault_metadata(vault_path)
    logger.debug(f"read_vault_metadata took {time.time() - t2:.2f}s")

    vault_id = metadata.get("vault_id") or fallback_vault_id
    if not vault_id:
        raise ValueError("Vault metadata is missing vault_id")

    assign_vault_location(
        context,
        vault_path=vault_path,
        vault_id=vault_id,
        vault_name=metadata.get("name") or fallback_alias or vault_path.name,
    )
    logger.debug(
        f"Total prepare_existing_vault_context took {time.time() - start:.2f}s"
    )


def attach_unlocked_key_service(
    context: VaultContext,
    *,
    vault_id: str,
    key_service: KeyService,
) -> None:
    """Attach an unlocked key service and master key to the vault context."""
    context.vault_id = vault_id
    context.local_data_path = local_data_path_for(context.app_data_dir, vault_id)
    ensure_local_runtime_dirs(context.local_data_path)
    context.key_service = key_service
    context.master_key = key_service.master_key
