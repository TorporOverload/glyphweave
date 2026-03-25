from __future__ import annotations

import base64
import json
from typing import Any

from app.core.domain.sync.hashing import canonical_json_bytes
from app.core.domain.sync.models import VaultEvent
from app.infrastructure.crypto.primitives.aes_gcm import (
    decrypt_event_bytes,
    encrypt_event_bytes,
)

from .event_store_config import EventStoreConfig

ENVELOPE_VERSION = 1
ENCRYPTED_MODE = "encrypted"
PLAINTEXT_MODE = "plaintext"


def encrypt_event(
    *,
    event: VaultEvent,
    event_hash: str,
    config: EventStoreConfig,
) -> dict[str, Any]:
    nonce, ciphertext = encrypt_event_bytes(
        plaintext=canonical_json_bytes(event.to_dict()),
        event_hash=event_hash,
        device_id=event.device_id,
        master_key=config.master_key.view(),
        vault_id=config.vault_id.encode("utf-8"),
        version=ENVELOPE_VERSION,
    )
    return {
        "version": ENVELOPE_VERSION,
        "mode": ENCRYPTED_MODE,
        "event_hash": event_hash,
        "device_id": event.device_id,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_event(
    *,
    envelope: dict[str, Any],
    config: EventStoreConfig,
) -> VaultEvent:
    event_hash = str(envelope["event_hash"])
    device_id = str(envelope["device_id"])
    version = int(envelope["version"])
    nonce = base64.b64decode(str(envelope["nonce"]))
    ciphertext = base64.b64decode(str(envelope["ciphertext"]))
    plaintext = decrypt_event_bytes(
        nonce=nonce,
        ciphertext=ciphertext,
        event_hash=event_hash,
        device_id=device_id,
        master_key=config.master_key.view(),
        vault_id=config.vault_id.encode("utf-8"),
        version=version,
    )
    event = VaultEvent.from_dict(json.loads(plaintext.decode("utf-8")))
    if event.device_id != device_id:
        raise ValueError(
            "Encrypted event header device_id does not match decrypted payload"
        )
    return event


def is_encrypted_envelope(payload: dict[str, Any]) -> bool:
    return payload.get("mode") == ENCRYPTED_MODE


def is_plaintext_envelope(payload: dict[str, Any]) -> bool:
    return payload.get("mode") == PLAINTEXT_MODE


def plaintext_envelope(*, event: VaultEvent, event_hash: str) -> dict[str, Any]:
    return {
        "version": ENVELOPE_VERSION,
        "mode": PLAINTEXT_MODE,
        "event_hash": event_hash,
        "event": event.to_dict(),
    }
