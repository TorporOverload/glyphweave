from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Final

from app.common.device_id import ensure_device_id

APP_DATA_ENV_VAR = "GLYPHWEAVE_APP_DATA_DIR"
EVENT_ENCRYPTION_ENV_VAR = "GLYPHWEAVE_EVENT_ENCRYPTION"
DEBUG_ENV_VAR = "GLYPHWEAVE_DEBUG"
LOG_FILE_ENV_VAR = "GLYPHWEAVE_LOG_FILE"
ERROR_LOG_FILE_ENV_VAR = "GLYPHWEAVE_ERROR_LOG_FILE"
DEFAULT_APP_DATA_DIR = Path.home() / ".glyphweave"
VAULTS_REGISTRY_FILE = "vaults.json"
APP_CONFIG_FILE = "config.json"
DEVICE_FILE = "device.json"
LOGS_DIR = "logs"
VAULTS_DIR = "vaults"
DEFAULT_DEBUG_LEVEL: Final[int] = 0
DEFAULT_EVENT_ENCRYPTION_ENABLED: Final[bool] = True
_FALSE_ENV_VALUES: Final[frozenset[str]] = frozenset({"0", "false", "no", "off"})
_TRUE_ENV_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})


def _get_env_str(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _get_env_int(name: str, default: int) -> int:
    value = _get_env_str(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_env_bool(name: str, default: bool) -> bool:
    value = _get_env_str(name)
    if value is None:
        return default
    lowered = value.lower()
    if lowered in _TRUE_ENV_VALUES:
        return True
    if lowered in _FALSE_ENV_VALUES:
        return False
    return default


def _get_env_path(name: str) -> Path | None:
    value = _get_env_str(name)
    if value is None:
        return None
    return Path(value).expanduser()


def get_app_data_dir() -> Path:
    """Return the application data directory, preferring the environment variable
    override."""
    return _get_env_path(APP_DATA_ENV_VAR) or DEFAULT_APP_DATA_DIR


def get_vaults_data_dir() -> Path:
    """Return the vault-local data directory inside the application root."""
    return get_app_data_dir() / VAULTS_DIR


def get_debug_level() -> int:
    """Return the configured debug level."""
    return max(_get_env_int(DEBUG_ENV_VAR, DEFAULT_DEBUG_LEVEL), 0)


def get_log_file_path() -> Path:
    """Return the debug log file path."""
    configured = _get_env_path(LOG_FILE_ENV_VAR)
    if configured is not None:
        return configured
    return ensure_app_data_layout(get_app_data_dir()) / LOGS_DIR / "debug.log"


def get_error_log_file_path() -> Path:
    """Return the error log file path."""
    configured = _get_env_path(ERROR_LOG_FILE_ENV_VAR)
    if configured is not None:
        return configured
    return ensure_app_data_layout(get_app_data_dir()) / LOGS_DIR / "error.log"


def is_event_encryption_enabled() -> bool:
    """Return whether encrypted event objects are enabled."""
    return _get_env_bool(
        EVENT_ENCRYPTION_ENV_VAR,
        DEFAULT_EVENT_ENCRYPTION_ENABLED,
    )


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
    ensure_device_id(root)

    return root
