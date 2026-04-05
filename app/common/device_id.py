from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

DEVICE_FILE = "device.json"
DEVICE_ID_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_device_id(device_id: str | None) -> str:
    normalized = (device_id or "").strip()
    if not normalized:
        return "unknown-device"
    return DEVICE_ID_RE.sub("-", normalized).strip("-") or "unknown-device"


def _device_file(app_data_dir: Path) -> Path:
    return Path(app_data_dir) / DEVICE_FILE


def _read_device_payload(app_data_dir: Path) -> dict[str, Any]:
    device_file = _device_file(app_data_dir)
    device_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        payload = json.loads(device_file.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _normalize_alias_map(raw_aliases: Any) -> dict[str, str]:
    if not isinstance(raw_aliases, dict):
        return {}

    normalized: dict[str, str] = {}
    for raw_device_id, raw_alias in raw_aliases.items():
        device_id = sanitize_device_id(str(raw_device_id))
        alias = str(raw_alias or "").strip()
        if device_id == "unknown-device" or not alias:
            continue
        normalized[device_id] = alias
    return normalized


def _normalized_device_payload(data: dict[str, Any]) -> dict[str, Any]:
    device_id = sanitize_device_id(data.get("device_id"))
    if device_id == "unknown-device":
        device_id = str(uuid.uuid4())

    return {
        "device_id": device_id,
        "alias": str(data.get("alias") or data.get("name") or "").strip(),
        "status": str(data.get("status") or "active").strip() or "active",
        "global_aliases": _normalize_alias_map(
            data.get("global_aliases") or data.get("aliases")
        ),
    }


def _write_device_payload(app_data_dir: Path, payload: dict[str, Any]) -> None:
    _device_file(app_data_dir).write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def ensure_device_id(app_data_dir: Path) -> str:
    """Ensure the app data directory has a persistent device UUID."""
    existing = _read_device_payload(app_data_dir)
    payload = _normalized_device_payload(existing)
    if existing != payload:
        _write_device_payload(app_data_dir, payload)
    return str(payload["device_id"])


def load_device_id(app_data_dir: Path) -> str:
    """Load the configured device ID, creating a persistent UUID if missing."""
    return ensure_device_id(app_data_dir)


def load_device_profile(app_data_dir: Path) -> dict[str, Any]:
    """Return normalized device metadata for the local app data directory."""
    existing = _read_device_payload(app_data_dir)
    payload = _normalized_device_payload(existing)
    if existing != payload:
        _write_device_payload(app_data_dir, payload)
    return payload


def resolve_device_alias(app_data_dir: Path, device_id: str | None) -> str | None:
    """Resolve a locally configured global alias for a device ID."""
    normalized_device_id = sanitize_device_id(device_id)
    if normalized_device_id == "unknown-device":
        return None

    payload = load_device_profile(app_data_dir)
    if normalized_device_id == payload["device_id"]:
        return str(payload["alias"] or "").strip() or None
    return payload["global_aliases"].get(normalized_device_id)


def set_device_alias(
    app_data_dir: Path,
    device_id: str | None,
    alias: str | None,
) -> str | None:
    """Persist a local global alias for a device ID. Blank aliases clear it."""
    normalized_device_id = sanitize_device_id(device_id)
    if normalized_device_id == "unknown-device":
        raise ValueError("Device ID is required")

    payload = load_device_profile(app_data_dir)
    normalized_alias = str(alias or "").strip() or None

    if normalized_device_id == payload["device_id"]:
        payload["alias"] = normalized_alias or ""
    elif normalized_alias is None:
        payload["global_aliases"].pop(normalized_device_id, None)
    else:
        payload["global_aliases"][normalized_device_id] = normalized_alias

    _write_device_payload(app_data_dir, payload)
    return normalized_alias


def default_frontier_alias(app_data_dir: Path, device_id: str | None) -> str:
    """Return the default synced alias to write into a device frontier file."""
    return resolve_device_alias(app_data_dir, device_id) or ""
