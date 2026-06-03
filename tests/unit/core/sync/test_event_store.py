import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.hashing import (
    canonical_event_body,
    canonical_json_bytes,
    hash_event,
)
from app.core.domain.sync.models import HybridLogicalClock, VaultEvent
from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.infrastructure.persistence.event_store import EventIntegrityError, EventStore
from app.infrastructure.persistence.event_store_config import EventStoreConfig


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


def _store(vault_path, *, encryption_enabled: bool = True) -> EventStore:
    return EventStore(
        EventStoreConfig(
            vault_path=vault_path,
            vault_id="vault-1",
            master_key=SecureMemory(b"k" * 32),
            encryption_enabled=encryption_enabled,
        )
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


def test_append_event_writes_encrypted_object_and_updates_frontier(tmp_path) -> None:
    store = _store(tmp_path / "vault")

    stored = store.append_event(_event())

    assert stored.event_hash is not None
    object_path = store.object_path(stored.event_hash)
    payload = json.loads(object_path.read_text(encoding="utf-8"))
    assert object_path.exists()
    assert object_path.parent == store.objects_dir
    assert payload["mode"] == "encrypted"
    assert "ciphertext" in payload
    assert store.read_frontier("device-a") == [stored.event_hash]
    frontier_payload = json.loads(
        store.root_path("device-a").read_text(encoding="utf-8")
    )
    assert frontier_payload["mode"] == "encrypted"
    assert frontier_payload["kind"] == "frontier"


def test_append_event_writes_plaintext_envelope_when_encryption_disabled(
    tmp_path,
) -> None:
    store = _store(tmp_path / "vault", encryption_enabled=False)

    stored = store.append_event(_event())

    payload = json.loads(
        store.object_path(stored.event_hash or "").read_text(encoding="utf-8")
    )
    assert payload["mode"] == "plaintext"
    assert payload["event"]["event_id"] == stored.event_id
    frontier_payload = json.loads(
        store.root_path("device-a").read_text(encoding="utf-8")
    )
    assert frontier_payload == {
        "alias": "",
        "device_id": "device-a",
        "frontier": [stored.event_hash],
        "updated_at": frontier_payload["updated_at"],
    }


def test_write_frontier_persists_alias_in_plaintext_mode(tmp_path) -> None:
    store = _store(tmp_path / "vault", encryption_enabled=False)

    store.write_frontier("device-a", ["hash-1"], alias="Work Laptop")

    payload = json.loads(store.root_path("device-a").read_text(encoding="utf-8"))
    assert payload["device_id"] == "device-a"
    assert payload["alias"] == "Work Laptop"
    assert payload["frontier"] == ["hash-1"]
    assert store.read_frontier_record("device-a")["alias"] == "Work Laptop"


def test_append_event_preserves_existing_frontier_alias(tmp_path) -> None:
    store = _store(tmp_path / "vault", encryption_enabled=False)
    store.write_frontier("device-a", ["hash-1"], alias="Work Laptop")

    stored = store.append_event(_event("evt-2"))

    assert store.read_frontier("device-a") == [stored.event_hash]
    assert store.read_frontier_record("device-a")["alias"] == "Work Laptop"


def test_load_event_round_trips_encrypted_event(tmp_path) -> None:
    store = _store(tmp_path / "vault")
    stored = store.append_event(_event())

    loaded = store.load_event(stored.event_hash or "")

    assert loaded.event_id == stored.event_id
    assert loaded.event_hash == stored.event_hash
    assert loaded.payload == stored.payload


def test_discover_events_returns_all_valid_encrypted_objects(tmp_path) -> None:
    store = _store(tmp_path / "vault")
    first = store.append_event(_event("evt-1"))
    second = store.append_event(_event("evt-2"))

    discovered = store.discover_events()

    assert [item.event.event_hash for item in discovered] == [
        first.event_hash,
        second.event_hash,
    ]


def test_event_store_rejects_bare_path() -> None:
    with pytest.raises(TypeError):
        EventStore(Path("/tmp/fake-vault"))  # nosec: B108 - test fixture only


def test_load_event_supports_plaintext_envelopes_when_encryption_disabled(tmp_path) -> None:
    legacy_store = _store(tmp_path / "vault", encryption_enabled=False)
    stored = legacy_store.append_event(_event())

    encrypted_capable = _store(tmp_path / "vault")
    loaded = encrypted_capable.load_event(stored.event_hash or "")

    assert loaded.event_id == stored.event_id
    assert loaded.payload == stored.payload


def test_iter_frontier_hashes_returns_known_head_hashes(tmp_path) -> None:
    store = _store(tmp_path / "vault")
    first = store.append_event(_event("evt-1"))
    second = store.append_event(
        VaultEvent(
            event_id="evt-2",
            type=EventType.FILE_ADD,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=1001, logical=0, device_id="device-b"),
            payload=first.payload,
            parents=[],
        )
    )

    assert store.iter_frontier_hashes() == {
        first.event_hash,
        second.event_hash,
    }


def test_load_event_raises_when_encrypted_object_is_tampered(tmp_path) -> None:
    store = _store(tmp_path / "vault")
    stored = store.append_event(_event())
    path = store.object_path(stored.event_hash or "")
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["ciphertext"] = payload["ciphertext"][:-4] + "AAAA"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    with pytest.raises(InvalidTag):
        store.load_event(stored.event_hash or "")


def test_load_event_raises_when_plaintext_object_is_tampered(tmp_path) -> None:
    store = _store(tmp_path / "vault", encryption_enabled=False)
    stored = store.append_event(_event())
    path = store.object_path(stored.event_hash or "")
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["event"]["payload"]["name"] = "tampered.txt"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    with pytest.raises(EventIntegrityError):
        store.load_event(stored.event_hash or "")
