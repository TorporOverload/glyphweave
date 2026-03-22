from __future__ import annotations

import json
import uuid
from pathlib import Path

import sqlcipher3

from app.core.service.db_dump_service import (
    DB_DUMP_THRESHOLD_BYTES,
    DBDumpService,
    load_device_id,
    restore_latest_db_dump,
)
from app.core.sync.event_store import EventStore
from app.core.sync.event_types import EventType


def test_load_device_id_generates_and_persists_uuid_when_missing(tmp_path: Path) -> None:
    device_id = load_device_id(tmp_path)

    assert uuid.UUID(device_id).version == 4
    payload = json.loads((tmp_path / "device.json").read_text(encoding="utf-8"))
    assert payload["device_id"] == device_id
    assert payload["status"] == "active"


def test_db_dump_service_creates_initial_dump_with_event(monkeypatch, tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"x" * 1024)

    service = DBDumpService(
        vault_path=vault_path,
        db_path=db_path,
        db_key_hex="ab" * 32,
        device_id="device:1",
    )

    monkeypatch.setattr(
        service,
        "_backup_database_online",
        lambda destination: destination.write_bytes(b"dump"),
    )

    dump_path = service.maybe_create_dump()

    assert dump_path is not None
    assert dump_path.name.endswith("-db")
    assert dump_path.name.startswith("device-1-")
    event_path = vault_path / "events" / "db_dumps" / f"{dump_path.name}.json"
    assert event_path.exists()
    payload = json.loads(event_path.read_text(encoding="utf-8"))
    assert payload["type"] == "db_dump_created"
    assert payload["dump_name"] == dump_path.name
    assert payload["db_size_bytes"] == 1024
    discovered = EventStore(vault_path).discover_events()
    assert len(discovered) == 1
    assert discovered[0].event.type == EventType.DB_DUMP_CREATED
    assert discovered[0].event.payload["dump_name"] == dump_path.name


def test_db_dump_service_skips_until_threshold_crossed(monkeypatch, tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"x" * 1024)

    service = DBDumpService(
        vault_path=vault_path,
        db_path=db_path,
        db_key_hex="ab" * 32,
        device_id="device-1",
    )

    monkeypatch.setattr(
        service,
        "_backup_database_online",
        lambda destination: destination.write_bytes(b"dump"),
    )

    first_dump = service.maybe_create_dump()
    assert first_dump is not None

    db_path.write_bytes(b"x" * (1024 + 128))
    assert service.maybe_create_dump() is None

    db_path.write_bytes(b"x" * (1024 + DB_DUMP_THRESHOLD_BYTES))
    second_dump = service.maybe_create_dump()
    assert second_dump is not None
    assert second_dump != first_dump


def test_db_dump_service_keeps_only_three_latest_versions(
    monkeypatch, tmp_path: Path
) -> None:
    vault_path = tmp_path / "vault"
    db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"x" * 1024)

    service = DBDumpService(
        vault_path=vault_path,
        db_path=db_path,
        db_key_hex="ab" * 32,
        device_id="device-1",
        threshold_bytes=1,
        max_backups=3,
    )

    counter = {"value": 0}

    def _copy(destination: Path) -> None:
        counter["value"] += 1
        destination.write_text(f"dump-{counter['value']}", encoding="utf-8")

    monkeypatch.setattr(service, "_backup_database_online", _copy)
    timestamps = iter(
        [
            "20260322T000001Z",
            "20260322T000002Z",
            "20260322T000003Z",
            "20260322T000004Z",
        ]
    )
    monkeypatch.setattr(
        "app.core.service.db_dump_service.datetime",
        type(
            "_FakeDatetime",
            (),
            {
                "now": staticmethod(
                    lambda tz=None: type(
                        "_Stamp",
                        (),
                        {"strftime": lambda self, fmt: next(timestamps)},
                    )()
                )
            },
        ),
    )

    for size in (1024, 2048, 3072, 4096):
        db_path.write_bytes(b"x" * size)
        assert service.maybe_create_dump() is not None

    dump_files = sorted(
        path.name for path in (vault_path / "db_dumps").iterdir() if path.is_file()
    )
    event_files = sorted(
        path.name
        for path in (vault_path / "events" / "db_dumps").iterdir()
        if path.is_file()
    )

    assert len(dump_files) == 3
    assert dump_files == [
        "device-1-20260322T000002Z-db",
        "device-1-20260322T000003Z-db",
        "device-1-20260322T000004Z-db",
    ]
    assert event_files == [f"{name}.json" for name in dump_files]


def test_restore_latest_db_dump_uses_newest_manifest(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    dumps_dir = vault_path / "db_dumps"
    events_dir = vault_path / "events" / "db_dumps"
    dumps_dir.mkdir(parents=True, exist_ok=True)
    events_dir.mkdir(parents=True, exist_ok=True)
    db_key_hex = "ab" * 32

    def _write_dump(path: Path, value: str) -> None:
        conn = sqlcipher3.connect(str(path))
        try:
            conn.execute(f"PRAGMA key = \"x'{db_key_hex}'\"")
            conn.execute("CREATE TABLE marker (value TEXT)")
            conn.execute("INSERT INTO marker(value) VALUES (?)", (value,))
            conn.commit()
        finally:
            conn.close()

    older_dump = dumps_dir / "device-1-20260322T000001Z-db"
    newer_dump = dumps_dir / "device-1-20260322T000002Z-db"
    _write_dump(older_dump, "older")
    _write_dump(newer_dump, "newer")
    (events_dir / f"{older_dump.name}.json").write_text(
        json.dumps({"created_at": "20260322T000001Z", "db_size_bytes": older_dump.stat().st_size}),
        encoding="utf-8",
    )
    (events_dir / f"{newer_dump.name}.json").write_text(
        json.dumps({"created_at": "20260322T000002Z", "db_size_bytes": newer_dump.stat().st_size}),
        encoding="utf-8",
    )

    restored_path = tmp_path / "local" / "vault.db"
    restored_from = restore_latest_db_dump(
        vault_path=vault_path,
        db_path=restored_path,
        db_key_hex=db_key_hex,
    )

    assert restored_from == newer_dump
    restored = sqlcipher3.connect(str(restored_path))
    try:
        restored.execute(f"PRAGMA key = \"x'{db_key_hex}'\"")
        row = restored.execute("SELECT value FROM marker").fetchone()
    finally:
        restored.close()
    assert row == ("newer",)
