from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from app.config import (
    VAULTS_REGISTRY_FILE,
    ensure_app_data_layout,
    get_app_data_dir,
)
from app.core.vault_layout import metadata_path

APP_DATA_DIR = get_app_data_dir()
VAULTS_REGISTRY = APP_DATA_DIR / VAULTS_REGISTRY_FILE


def load_registry() -> list[dict]:
    """Load and return all vault registry entries from disk."""
    ensure_app_data_layout(APP_DATA_DIR)
    if not VAULTS_REGISTRY.exists():
        return []
    with open(VAULTS_REGISTRY, "r", encoding="utf-8") as f:
        return json.load(f)


def save_registry(entries: list[dict]) -> None:
    """Persist the given vault registry entries to disk."""
    ensure_app_data_layout(APP_DATA_DIR)
    with open(VAULTS_REGISTRY, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=4)


def upsert_registry(vault_id: str, vault_alias: str, vault_path: str) -> None:
    """Insert or update a vault entry in the registry."""
    entries = load_registry()
    now = datetime.now(timezone.utc).isoformat()

    for entry in entries:
        if entry["vault_id"] == vault_id:
            entry["vault_alias"] = vault_alias
            entry["path"] = vault_path
            entry["last_opened"] = now
            save_registry(entries)
            return

    entries.append(
        {
            "vault_id": vault_id,
            "vault_alias": vault_alias,
            "path": vault_path,
            "last_opened": now,
        }
    )
    save_registry(entries)


def write_vault_metadata(vault_dir: Path, vault_id: str, name: str) -> None:
    """Write vault identity metadata to the vault directory."""
    meta = {
        "vault_id": vault_id,
        "name": name,
        "version": 1,
        "created": datetime.now(timezone.utc).isoformat(),
        "schema_version": 1,
    }
    with open(metadata_path(vault_dir), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=4)


def read_vault_metadata(vault_dir: Path) -> dict:
    """Read and return vault metadata from the vault directory."""
    meta_path = metadata_path(vault_dir)
    if not meta_path.exists():
        raise FileNotFoundError(f".glyphweave_vault not found in {vault_dir}")
    with open(meta_path, "r", encoding="utf-8") as f:
        return json.load(f)
