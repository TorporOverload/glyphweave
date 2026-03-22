from __future__ import annotations

import hashlib
import json
from typing import Any

from app.core.sync.models import VaultEvent


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize a value to canonical JSON bytes for stable hashing."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_event_body(event: VaultEvent) -> dict[str, Any]:
    """Return the hashable event body excluding the event_hash field itself."""
    return {
        "event_id": event.event_id,
        "type": event.type.value,
        "device_id": event.device_id,
        "hlc": event.hlc.to_dict(),
        "payload": event.payload,
        "parents": list(event.parents),
    }


def hash_event(event: VaultEvent) -> str:
    """Compute the SHA-256 hash of a canonical event body."""
    body_bytes = canonical_json_bytes(canonical_event_body(event))
    return hashlib.sha256(body_bytes).hexdigest()
