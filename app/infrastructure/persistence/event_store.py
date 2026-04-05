from __future__ import annotations

import json
import base64
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.common.paths.vault_layout import EVENTS_DIR
from app.core.domain.sync.hashing import canonical_json_bytes
from app.core.domain.sync.hashing import hash_event
from app.core.domain.sync.models import DiscoveredEvent, VaultEvent
from app.infrastructure.crypto.primitives.aes_gcm import (
    decrypt_event_bytes,
    encrypt_event_bytes,
)

from .event_crypto import (
    decrypt_event,
    encrypt_event,
    is_encrypted_envelope,
    is_plaintext_envelope,
    plaintext_envelope,
)
from .event_store_config import EventStoreConfig

OBJECTS_DIR = "objects"
ROOTS_DIR = "roots"
FRONTIER_RECORD_VERSION = 1
FRONTIER_RECORD_KIND = "frontier"


class EventIntegrityError(ValueError):
    """Raised when an on-disk event does not match its expected hash."""


class EventStore:
    """Append-only Merkle-style event store rooted inside a vault."""

    def __init__(self, config: EventStoreConfig | Path) -> None:
        self._config = config if isinstance(config, EventStoreConfig) else None
        self._vault_path = Path(
            config.vault_path if isinstance(config, EventStoreConfig) else config
        )

    @property
    def events_dir(self) -> Path:
        path = self._vault_path / EVENTS_DIR
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def objects_dir(self) -> Path:
        path = self.events_dir / OBJECTS_DIR
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def roots_dir(self) -> Path:
        path = self.events_dir / ROOTS_DIR
        path.mkdir(parents=True, exist_ok=True)
        return path

    def append_event(
        self,
        event: VaultEvent,
        *,
        frontier_alias: str | None = None,
    ) -> VaultEvent:
        """Persist an immutable event object and update the writer frontier."""
        event_hash = hash_event(event)
        stored = replace(event, event_hash=event_hash)
        object_path = self.object_path(event_hash)
        object_path.parent.mkdir(parents=True, exist_ok=True)
        if not object_path.exists():
            object_path.write_text(
                json.dumps(
                    self._serialize_event_payload(stored, event_hash),
                    sort_keys=True,
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

        alias = frontier_alias
        if alias is None:
            alias = str(
                self.read_frontier_record(stored.device_id).get("alias") or ""
            ).strip()
        self.write_frontier(stored.device_id, [event_hash], alias=alias)
        return stored

    def object_path(self, event_hash: str) -> Path:
        return self.objects_dir / f"{event_hash}.json"

    def root_path(self, device_id: str) -> Path:
        safe_device = device_id.replace("/", "_").replace("\\", "_")
        return self.roots_dir / f"{safe_device}.json"

    def load_event(self, event_hash: str, *, verify: bool = True) -> VaultEvent:
        path = self.object_path(event_hash)
        payload = json.loads(path.read_text(encoding="utf-8"))
        event = self._deserialize_event_payload(payload, event_hash)
        if verify:
            self.verify_event(event, expected_hash=event_hash)
        return event

    def verify_event(
        self,
        event: VaultEvent,
        *,
        expected_hash: str | None = None,
    ) -> None:
        computed_hash = hash_event(event)
        target_hash = expected_hash or event.event_hash
        if target_hash is None:
            raise EventIntegrityError("Missing expected event hash")
        if computed_hash != target_hash:
            raise EventIntegrityError(
                f"Event hash mismatch: expected {target_hash}, computed {computed_hash}"
            )

    def discover_events(
        self,
        *,
        skip_hashes: set[str] | None = None,
    ) -> list[DiscoveredEvent]:
        discovered: list[DiscoveredEvent] = []
        for path in sorted(self.objects_dir.glob("*.json")):
            event_hash = path.stem
            if skip_hashes is not None and event_hash in skip_hashes:
                continue
            payload = json.loads(path.read_text(encoding="utf-8"))
            event = self._deserialize_event_payload(payload, event_hash)
            self.verify_event(event, expected_hash=event_hash)
            discovered.append(DiscoveredEvent(event=event, source_path=str(path)))
        return discovered

    def has_unprocessed_events(
        self,
        *,
        skip_hashes: set[str] | None = None,
    ) -> bool:
        """Return True if at least one unprocessed event exists (no deserialization)."""
        for path in self.objects_dir.glob("*.json"):
            event_hash = path.stem
            if skip_hashes is not None and event_hash in skip_hashes:
                continue
            return True
        return False

    def read_frontier(self, device_id: str) -> list[str]:
        payload = self.read_frontier_record(device_id)
        return [str(item) for item in payload.get("frontier", [])]

    def read_frontier_record(self, device_id: str) -> dict[str, Any]:
        path = self.root_path(device_id)
        if not path.exists():
            return self._default_frontier_record(device_id)
        payload = json.loads(path.read_text(encoding="utf-8"))
        record = self._deserialize_frontier_payload(device_id, payload)
        return self._normalize_frontier_record(record, device_id=device_id)

    def iter_frontier_hashes(self) -> set[str]:
        hashes: set[str] = set()
        for path in self.roots_dir.glob("*.json"):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                record = self._deserialize_frontier_payload(path.stem, payload)
            except (OSError, json.JSONDecodeError):
                continue
            except Exception:
                continue
            for item in record.get("frontier", []):
                if item:
                    hashes.add(str(item))
        return hashes

    def write_frontier(
        self,
        device_id: str,
        frontier: list[str],
        *,
        alias: str = "",
    ) -> None:
        path = self.root_path(device_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        record = self._normalize_frontier_record(
            {
                "device_id": device_id,
                "alias": alias,
                "frontier": list(frontier),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
            device_id=device_id,
        )
        payload = self._serialize_frontier_payload(record)
        path.write_text(
            json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def write_frontier_alias(self, device_id: str, alias: str = "") -> None:
        record = self.read_frontier_record(device_id)
        self.write_frontier(
            device_id,
            [str(item) for item in record.get("frontier", [])],
            alias=alias,
        )

    def _default_frontier_record(self, device_id: str) -> dict[str, Any]:
        return {
            "device_id": device_id,
            "alias": "",
            "frontier": [],
            "updated_at": None,
        }

    def _normalize_frontier_record(
        self,
        payload: dict[str, Any],
        *,
        device_id: str,
    ) -> dict[str, Any]:
        return {
            "device_id": str(payload.get("device_id") or device_id),
            "alias": str(payload.get("alias") or "").strip(),
            "frontier": [str(item) for item in payload.get("frontier", []) if item],
            "updated_at": str(payload.get("updated_at")) if payload.get("updated_at") else None,
        }

    def _serialize_frontier_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._config is None or not self._config.encryption_enabled:
            return payload

        device_id = str(payload["device_id"])
        record_key = f"frontier:{device_id}"
        nonce, ciphertext = encrypt_event_bytes(
            plaintext=canonical_json_bytes(payload),
            event_hash=record_key,
            device_id=device_id,
            master_key=self._config.master_key.view(),
            vault_id=self._config.vault_id.encode("utf-8"),
            version=FRONTIER_RECORD_VERSION,
        )
        return {
            "version": FRONTIER_RECORD_VERSION,
            "kind": FRONTIER_RECORD_KIND,
            "mode": "encrypted",
            "device_id": device_id,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }

    def _deserialize_frontier_payload(
        self,
        device_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if payload.get("kind") == FRONTIER_RECORD_KIND and payload.get("mode") == "encrypted":
            if self._config is None:
                raise EventIntegrityError(
                    "Encrypted frontier record requires an initialized EventStoreConfig"
                )
            envelope_device_id = str(payload.get("device_id") or device_id)
            record_key = f"frontier:{envelope_device_id}"
            plaintext = decrypt_event_bytes(
                nonce=base64.b64decode(str(payload["nonce"])),
                ciphertext=base64.b64decode(str(payload["ciphertext"])),
                event_hash=record_key,
                device_id=envelope_device_id,
                master_key=self._config.master_key.view(),
                vault_id=self._config.vault_id.encode("utf-8"),
                version=int(payload.get("version", FRONTIER_RECORD_VERSION)),
            )
            record = json.loads(plaintext.decode("utf-8"))
            if str(record.get("device_id") or envelope_device_id) != envelope_device_id:
                raise EventIntegrityError(
                    "Encrypted frontier record device_id does not match decrypted payload"
                )
            return record

        if "frontier" in payload:
            return payload

        raise EventIntegrityError("Invalid frontier record payload")

    def _serialize_event_payload(
        self, event: VaultEvent, event_hash: str
    ) -> dict[str, Any]:
        if self._config is None:
            return event.to_dict()
        if self._config.encryption_enabled:
            return encrypt_event(
                event=event, event_hash=event_hash, config=self._config
            )
        return plaintext_envelope(event=event, event_hash=event_hash)

    def _deserialize_event_payload(
        self,
        payload: dict[str, Any],
        event_hash: str,
    ) -> VaultEvent:
        if is_encrypted_envelope(payload):
            if self._config is None:
                raise EventIntegrityError(
                    "Encrypted event object requires an initialized EventStoreConfig"
                )
            event = decrypt_event(envelope=payload, config=self._config)
        elif is_plaintext_envelope(payload):
            event = VaultEvent.from_dict(dict(payload.get("event", {})))
        else:
            event = VaultEvent.from_dict(payload)

        if event.event_hash is not None and event.event_hash != event_hash:
            raise EventIntegrityError(
                "Event payload hash does not match object filename hash"
            )
        return event
