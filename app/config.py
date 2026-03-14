from __future__ import annotations

import os
import json
from pathlib import Path

APP_DATA_ENV_VAR = "GLYPHWEAVE_APP_DATA_DIR"
VAULTS_DATA_ENV_VAR = "GLYPHWEAVE_LOCAL_DIR"
DEFAULT_APP_DATA_DIR = Path.home() / ".glyphweave"
VAULTS_REGISTRY_FILE = "vaults.json"
APP_CONFIG_FILE = "config.json"
DEVICE_FILE = "device.json"
LOGS_DIR = "logs"
VAULTS_DIR = "vaults"


def get_app_data_dir() -> Path:
    """Return the application data directory, preferring the environment variable
    override."""
    configured = os.environ.get(APP_DATA_ENV_VAR)
    if configured:
        return Path(configured).expanduser()
    return DEFAULT_APP_DATA_DIR


def get_vaults_data_dir() -> Path:
    """Return the vaults data directory, preferring the environment variable
    override."""
    configured = os.environ.get(VAULTS_DATA_ENV_VAR)
    if configured:
        return Path(configured).expanduser()
    return get_app_data_dir() / VAULTS_DIR


def _ensure_json_file(path: Path, default_value) -> None:
    """Create a JSON file with default_value if it does not already exist."""
    if path.exists():
        return
    with open(path, "w", encoding="utf-8") as f:
        json.dump(default_value, f, indent=2)


def ensure_app_data_layout(app_data_dir: Path | None = None) -> Path:
    """Create the application data directory structure and default config files."""
    root = Path(app_data_dir or get_app_data_dir()).expanduser()
    root.mkdir(parents=True, exist_ok=True)

    (root / VAULTS_DIR).mkdir(parents=True, exist_ok=True)
    (root / LOGS_DIR).mkdir(parents=True, exist_ok=True)

    _ensure_json_file(root / VAULTS_REGISTRY_FILE, [])
    _ensure_json_file(root / APP_CONFIG_FILE, {})
    _ensure_json_file(
        root / DEVICE_FILE,
        {"device_id": None, "name": None, "status": "inactive"},
    )

    return root
