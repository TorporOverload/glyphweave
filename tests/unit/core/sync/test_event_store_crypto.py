import json

import pytest

from cryptography.exceptions import InvalidTag

from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.hashing import hash_event
from app.core.domain.sync.models import HybridLogicalClock, VaultEvent
from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.infrastructure.persistence.event_store import EventIntegrityError, EventStore
from app.infrastructure.persistence.event_store_config import EventStoreConfig


def _event(
    event_id: str = "evt-1",
    payload: dict | None = None,
    device_id: str = "device-a",
) -> VaultEvent:
    return VaultEvent(
        event_id=event_id,
        type=EventType.FILE_ADD,
        device_id=device_id,
        hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id=device_id),
        payload=payload or {
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


class TestZeroLengthPayloadHandling:
    def test_append_event_with_empty_payload_encrypted(self, tmp_path) -> None:
        store = _store(tmp_path / "vault")
        event = VaultEvent(
            event_id="evt-empty",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={},
            parents=[],
        )

        stored = store.append_event(event)

        assert stored.event_hash is not None
        loaded = store.load_event(stored.event_hash or "")
        assert loaded.event_id == stored.event_id
        assert loaded.payload == {}

    def test_append_event_with_empty_payload_plaintext(self, tmp_path) -> None:
        store = _store(tmp_path / "vault", encryption_enabled=False)
        event = VaultEvent(
            event_id="evt-empty",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={},
            parents=[],
        )

        stored = store.append_event(event)

        loaded = store.load_event(stored.event_hash or "")
        assert loaded.payload == {}

    def test_load_event_with_minimal_plaintext_envelope(self, tmp_path) -> None:
        store = _store(tmp_path / "vault", encryption_enabled=False)
        event = VaultEvent(
            event_id="evt-minimal",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1, logical=0, device_id="device-a"),
            payload={},
            parents=[],
        )

        stored = store.append_event(event)
        loaded = store.load_event(stored.event_hash or "")

        assert loaded.event_id == "evt-minimal"
        assert loaded.payload == {}


class TestVeryLargePayloads:
    def test_append_event_with_large_payload_encrypted(self, tmp_path) -> None:
        store = _store(tmp_path / "vault")
        large_data = {"data": "x" * 100_000}
        event = _event("evt-large", payload=large_data)

        stored = store.append_event(event)

        assert stored.event_hash is not None
        loaded = store.load_event(stored.event_hash or "")
        assert loaded.payload == large_data

    def test_append_event_with_large_payload_plaintext(self, tmp_path) -> None:
        store = _store(tmp_path / "vault", encryption_enabled=False)
        large_data = {"data": "x" * 100_000}
        event = _event("evt-large", payload=large_data)

        stored = store.append_event(event)

        loaded = store.load_event(stored.event_hash or "")
        assert loaded.payload == large_data

    def test_discover_events_with_large_payloads(self, tmp_path) -> None:
        store = _store(tmp_path / "vault")
        large_data = {"data": "y" * 50_000}
        for i in range(3):
            event = _event(f"evt-large-{i}", payload=large_data)
            store.append_event(event)

        discovered = store.discover_events()

        assert len(discovered) == 3
        for item in discovered:
            assert item.event.payload == large_data


class TestIntegrityVerificationEdgeCases:
    def test_verify_event_with_missing_hash(self, tmp_path) -> None:
        store = _store(tmp_path / "vault")
        event = _event("evt-no-hash")
        no_hash_event = VaultEvent(
            event_id="evt-no-hash",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={},
            parents=[],
            event_hash=None,
        )

        with pytest.raises(EventIntegrityError, match="Missing expected event hash"):
            store.verify_event(no_hash_event)

    def test_verify_event_with_mismatched_hash(self, tmp_path) -> None:
        store = _store(tmp_path / "vault")
        event = _event("evt-tampered")
        computed_hash = hash_event(event)
        tampered_event = VaultEvent(
            event_id="evt-tampered",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"tampered": True},
            parents=[],
            event_hash=computed_hash,
        )

        with pytest.raises(EventIntegrityError, match="Event hash mismatch"):
            store.verify_event(tampered_event, expected_hash=computed_hash)

    def test_load_event_verify_false_skips_integrity_check(self, tmp_path) -> None:
        store = _store(tmp_path / "vault")
        stored = store.append_event(_event())
        path = store.object_path(stored.event_hash or "")
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["ciphertext"] = payload["ciphertext"][:-4] + "AAAA"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        with pytest.raises(InvalidTag):
            store.load_event(stored.event_hash or "", verify=False)

    def test_load_event_with_tampered_ciphertext_detected(self, tmp_path) -> None:
        store = _store(tmp_path / "vault")
        stored = store.append_event(_event())
        path = store.object_path(stored.event_hash or "")
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["ciphertext"] = payload["ciphertext"][:-4] + "AAAA"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        with pytest.raises(InvalidTag):
            store.load_event(stored.event_hash or "")

    def test_discover_events_with_invalid_hash(self, tmp_path) -> None:
        store = _store(tmp_path / "vault")
        event = _event("evt-invalid")
        stored = store.append_event(event)
        path = store.object_path(stored.event_hash or "")
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["event_hash"] = "invalid-hash"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        with pytest.raises(InvalidTag):
            store.discover_events()


class TestPlaintextModeBoundaryConditions:
    def test_plaintext_mode_missing_event_field(self, tmp_path) -> None:
        store = _store(tmp_path / "vault", encryption_enabled=False)
        stored = store.append_event(_event())
        path = store.object_path(stored.event_hash or "")
        payload = json.loads(path.read_text(encoding="utf-8"))
        del payload["event"]
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        with pytest.raises(KeyError):
            store.load_event(stored.event_hash or "")

    def test_plaintext_mode_tampered_payload_detected(self, tmp_path) -> None:
        store = _store(tmp_path / "vault", encryption_enabled=False)
        stored = store.append_event(_event())
        path = store.object_path(stored.event_hash or "")
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["event"]["payload"]["name"] = "hacked.txt"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        with pytest.raises(EventIntegrityError):
            store.load_event(stored.event_hash or "")

    def test_plaintext_mode_wrong_event_id(self, tmp_path) -> None:
        store = _store(tmp_path / "vault", encryption_enabled=False)
        stored = store.append_event(_event())
        path = store.object_path(stored.event_hash or "")
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["event"]["event_id"] = "wrong-id"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        with pytest.raises(EventIntegrityError):
            store.load_event(stored.event_hash or "")

    def test_switch_between_encrypted_and_plaintext_stores(self, tmp_path) -> None:
        encrypted_store = _store(tmp_path / "vault", encryption_enabled=True)
        original_event = _event("evt-switch")
        stored = encrypted_store.append_event(original_event)

        plaintext_store = _store(tmp_path / "vault", encryption_enabled=False)
        loaded = plaintext_store.load_event(stored.event_hash or "")

        assert loaded.event_id == "evt-switch"
        assert loaded.payload == original_event.payload

    def test_plaintext_mode_with_special_characters_in_payload(self, tmp_path) -> None:
        store = _store(tmp_path / "vault", encryption_enabled=False)
        event = _event(
            "evt-special",
            payload={
                "name": "文档.txt",
                "emoji": "🎉",
                "unicode": "\u00e9\u00e8\u00ea",
                "null_byte": "\x00",
            },
        )

        stored = store.append_event(event)
        loaded = store.load_event(stored.event_hash or "")

        assert loaded.payload["name"] == "文档.txt"
        assert loaded.payload["emoji"] == "🎉"
        assert loaded.payload["unicode"] == "\u00e9\u00e8\u00ea"
        assert loaded.payload["null_byte"] == "\x00"

    def test_plaintext_mode_with_deeply_nested_payload(self, tmp_path) -> None:
        store = _store(tmp_path / "vault", encryption_enabled=False)
        nested_payload = {"level1": {"level2": {"level3": {"level4": "deep"}}}}
        event = _event("evt-nested", payload=nested_payload)

        stored = store.append_event(event)
        loaded = store.load_event(stored.event_hash or "")

        assert loaded.payload == nested_payload

    def test_plaintext_mode_with_array_payload(self, tmp_path) -> None:
        store = _store(tmp_path / "vault", encryption_enabled=False)
        event = _event(
            "evt-array",
            payload={
                "items": [1, 2, 3],
                "mixed": ["string", 123, {"nested": True}],
            },
        )

        stored = store.append_event(event)
        loaded = store.load_event(stored.event_hash or "")

        assert loaded.payload == event.payload
