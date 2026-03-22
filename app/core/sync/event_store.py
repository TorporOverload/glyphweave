from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from app.core.sync.hashing import hash_event
from app.core.sync.models import DiscoveredEvent, VaultEvent
from app.core.vault_layout import EVENTS_DIR

OBJECTS_DIR = "objects"
ROOTS_DIR = "roots"


class EventIntegrityError(ValueError):
    """Raised when an on-disk event does not match its expected hash."""


class EventStore:
    """Append-only Merkle-style event store rooted inside a vault."""

    def __init__(self, vault_path: Path) -> None:
        self._vault_path = Path(vault_path)

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

    def append_event(self, event: VaultEvent) -> VaultEvent:
        """Persist an immutable event object and update the writer frontier."""
        event_hash = hash_event(event)
        stored = replace(event, event_hash=event_hash)
        object_path = self.object_path(event_hash)
        object_path.parent.mkdir(parents=True, exist_ok=True)
        if not object_path.exists():
            object_path.write_text(
                json.dumps(
                    stored.to_dict(), sort_keys=True, indent=2, ensure_ascii=False
                ),
                encoding="utf-8",
            )

        self.write_frontier(stored.device_id, [event_hash])
        return stored

    def object_path(self, event_hash: str) -> Path:
        return self.objects_dir / f"{event_hash}.json"

    def root_path(self, device_id: str) -> Path:
        safe_device = device_id.replace("/", "_").replace("\\", "_")
        return self.roots_dir / f"{safe_device}.json"

    def load_event(self, event_hash: str, *, verify: bool = True) -> VaultEvent:
        path = self.object_path(event_hash)
        payload = json.loads(path.read_text(encoding="utf-8"))
        event = VaultEvent.from_dict(payload)
        if verify:
            self.verify_event(event, expected_hash=event_hash)
        return event

    def verify_event(
        self, event: VaultEvent, *, expected_hash: str | None = None
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
            event = VaultEvent.from_dict(payload)
            self.verify_event(event, expected_hash=event_hash)
            discovered.append(DiscoveredEvent(event=event, source_path=str(path)))
        return discovered

    def read_frontier(self, device_id: str) -> list[str]:
        path = self.root_path(device_id)
        if not path.exists():
            return []
        payload = json.loads(path.read_text(encoding="utf-8"))
        return [str(item) for item in payload.get("frontier", [])]

    def write_frontier(self, device_id: str, frontier: list[str]) -> None:
        path = self.root_path(device_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "device_id": device_id,
            "frontier": list(frontier),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        path.write_text(
            json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
