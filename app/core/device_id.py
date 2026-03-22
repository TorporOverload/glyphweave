from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

DEVICE_FILE = "device.json"
_DEVICE_ID_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_device_id(device_id: str | None) -> str:
    normalized = (device_id or "").strip()
    if not normalized:
        return "unknown-device"
    return _DEVICE_ID_SAFE.sub("-", normalized).strip("-") or "unknown-device"


def ensure_device_id(app_data_dir: Path) -> str:
    """Ensure the app data directory has a persistent device UUID."""
    device_file = Path(app_data_dir) / DEVICE_FILE
    device_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = json.loads(device_file.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        data = {}

    existing = sanitize_device_id(data.get("device_id"))
    if existing != "unknown-device":
        return existing

    device_id = str(uuid.uuid4())
    payload = {
        "device_id": device_id,
        "name": data.get("name"),
        "status": data.get("status", "active"),
    }
    device_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return device_id


def load_device_id(app_data_dir: Path) -> str:
    """Load the configured device ID, creating a persistent UUID if missing."""
    return ensure_device_id(app_data_dir)
