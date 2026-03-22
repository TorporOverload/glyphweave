import json

import pytest

from app.core.sync.event_store import EventIntegrityError, EventStore
from app.core.sync.event_types import EventType
from app.core.sync.hashing import canonical_event_body, canonical_json_bytes, hash_event
from app.core.sync.models import HybridLogicalClock, VaultEvent


def _event(event_id: str = "evt-1") -> VaultEvent:
    return VaultEvent(
        event_id=event_id,
        type=EventType.FILE_ADD,
        device_id="device-a",
        hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
        payload={
            "node_id": "node-1",
            "file_id": "file-1",
            "parent_node_id": None,
            "name": "report.txt",
            "blob_ids": ["blob-1.enc"],
            "content_hash": "hash-1",
            "mime_type": "text/plain",
            "file_size_bytes": 5,
            "encrypted_size_bytes": 11,
        },
        parents=[],
    )


def test_canonical_json_bytes_is_stable() -> None:
    left = {"b": 2, "a": 1}
    right = {"a": 1, "b": 2}

    assert canonical_json_bytes(left) == canonical_json_bytes(right)


def test_hash_event_ignores_event_hash_field() -> None:
    event = _event()
    first_hash = hash_event(event)
    with_hash = VaultEvent.from_dict(
        {
            **event.to_dict(),
            "event_hash": "placeholder",
        }
    )

    assert hash_event(with_hash) == first_hash
    assert canonical_event_body(event)["event_id"] == "evt-1"


def test_append_event_writes_object_and_updates_frontier(tmp_path) -> None:
    store = EventStore(tmp_path / "vault")

    stored = store.append_event(_event())

    assert stored.event_hash is not None
    object_path = store.object_path(stored.event_hash)
    assert object_path.exists()
    assert object_path.parent == store.objects_dir
    assert store.read_frontier("device-a") == [stored.event_hash]


def test_load_event_round_trips_from_disk(tmp_path) -> None:
    store = EventStore(tmp_path / "vault")
    stored = store.append_event(_event())

    loaded = store.load_event(stored.event_hash or "")

    assert loaded.event_id == stored.event_id
    assert loaded.event_hash == stored.event_hash
    assert loaded.payload == stored.payload


def test_discover_events_returns_all_valid_objects(tmp_path) -> None:
    store = EventStore(tmp_path / "vault")
    first = store.append_event(_event("evt-1"))
    second = store.append_event(_event("evt-2"))

    discovered = store.discover_events()

    assert [item.event.event_hash for item in discovered] == [
        first.event_hash,
        second.event_hash,
    ]


def test_load_event_raises_when_object_is_tampered(tmp_path) -> None:
    store = EventStore(tmp_path / "vault")
    stored = store.append_event(_event())
    path = store.object_path(stored.event_hash or "")
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["payload"]["name"] = "tampered.txt"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    with pytest.raises(EventIntegrityError):
        store.load_event(stored.event_hash or "")
