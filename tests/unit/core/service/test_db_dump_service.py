from __future__ import annotations

import json
import uuid
from pathlib import Path
from threading import Timer
from typing import Callable
from types import SimpleNamespace

import sqlcipher3
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.infrastructure.persistence.db_dump_service import (
    DB_DUMP_CHECK_DELAY_SECONDS,
    DB_DUMP_THRESHOLD_BYTES,
    DBDumpService,
    flush_db_dump_hook,
    install_db_dump_hook,
    load_device_id,
    restore_latest_db_dump,
)
from app.common.device_id import resolve_device_alias, set_device_alias
from app.infrastructure.persistence.event_store import EventStore
from app.infrastructure.persistence.event_store_config import EventStoreConfig
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import HybridLogicalClock


def _store(vault_path: Path) -> EventStore:
    return EventStore(
        EventStoreConfig(
            vault_path=vault_path,
            vault_id="vault-1",
            master_key=SecureMemory(b"k" * 32),
            encryption_enabled=True,
        )
    )


def test_load_device_id_generates_and_persists_uuid_when_missing(
    tmp_path: Path,
) -> None:
    device_id = load_device_id(tmp_path)

    assert uuid.UUID(device_id).version == 4
    payload = json.loads((tmp_path / "device.json").read_text(encoding="utf-8"))
    assert payload["device_id"] == device_id
    assert payload["alias"] == ""
    assert payload["global_aliases"] == {}
    assert payload["status"] == "active"


def test_set_device_alias_persists_local_and_remote_names(tmp_path: Path) -> None:
    device_id = load_device_id(tmp_path)

    assert set_device_alias(tmp_path, device_id, "My Desktop") == "My Desktop"
    assert set_device_alias(tmp_path, "device-b", "Work Laptop") == "Work Laptop"
    assert resolve_device_alias(tmp_path, device_id) == "My Desktop"
    assert resolve_device_alias(tmp_path, "device-b") == "Work Laptop"

    cleared = set_device_alias(tmp_path, "device-b", None)
    assert cleared is None
    assert resolve_device_alias(tmp_path, "device-b") is None


def test_db_dump_service_creates_initial_dump_with_event(
    monkeypatch, tmp_path: Path
) -> None:
    vault_path = tmp_path / "vault"
    db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"x" * 1024)
    store = _store(vault_path)

    service = DBDumpService(
        vault_path=vault_path,
        db_path=db_path,
        db_key_hex="ab" * 32,
        device_id="device:1",
        event_store=store,
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
    discovered = store.discover_events()
    assert len(discovered) == 1
    assert discovered[0].event.type == EventType.DB_DUMP_CREATED
    assert discovered[0].event.payload["dump_name"] == dump_path.name


def test_db_dump_service_observes_only_frontier_heads(
    monkeypatch, tmp_path: Path
) -> None:
    vault_path = tmp_path / "vault"
    db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"x" * 1024)
    store = _store(vault_path)

    head_hashes = {"head-a", "head-b"}
    loaded_hashes: list[str] = []
    observed: list[dict[str, object]] = []

    monkeypatch.setattr(
        store,
        "discover_events",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("unexpected full event scan")
        ),
    )
    monkeypatch.setattr(store, "iter_frontier_hashes", lambda: head_hashes)

    def _load_event(event_hash: str):
        loaded_hashes.append(event_hash)
        wall_time = 1000 if event_hash == "head-a" else 2000
        return SimpleNamespace(
            hlc=HybridLogicalClock(
                wall_time=wall_time,
                logical=0,
                device_id=event_hash,
            )
        )

    monkeypatch.setattr(store, "load_event", _load_event)
    service = DBDumpService(
        vault_path=vault_path,
        db_path=db_path,
        db_key_hex="ab" * 32,
        device_id="device-1",
        event_store=store,
    )
    monkeypatch.setattr(service._clock, "observe", lambda value: observed.append(value))

    service._observe_existing_events()

    assert set(loaded_hashes) == head_hashes
    assert observed == [{"wall_time": 2000, "logical": 0, "device_id": "head-b"}]


def test_db_dump_service_skips_until_threshold_crossed(
    monkeypatch, tmp_path: Path
) -> None:
    vault_path = tmp_path / "vault"
    db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"x" * 1024)
    store = _store(vault_path)

    service = DBDumpService(
        vault_path=vault_path,
        db_path=db_path,
        db_key_hex="ab" * 32,
        device_id="device-1",
        event_store=store,
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
    store = _store(vault_path)

    service = DBDumpService(
        vault_path=vault_path,
        db_path=db_path,
        db_key_hex="ab" * 32,
        device_id="device-1",
        event_store=store,
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
        "app.infrastructure.persistence.db_dump_service.datetime",
        type(
            "_FakeDatetime",
            (),
            {
                "now": staticmethod(
                    lambda _tz=None: type(
                        "_Stamp",
                        (),
                        {"strftime": lambda self, _fmt: next(timestamps)},
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
        json.dumps(
            {
                "created_at": "20260322T000001Z",
                "db_size_bytes": older_dump.stat().st_size,
            }
        ),
        encoding="utf-8",
    )
    (events_dir / f"{newer_dump.name}.json").write_text(
        json.dumps(
            {
                "created_at": "20260322T000002Z",
                "db_size_bytes": newer_dump.stat().st_size,
            }
        ),
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


def test_schedule_dump_check_resets_timer(monkeypatch, tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"x" * 1024)
    store = _store(vault_path)
    fired: list[int] = []
    created_timers: list[_FakeTimer] = []

    class _FakeTimer(Timer):
        def __init__(self, delay: float, callback: Callable[[], None]) -> None:
            super().__init__(delay, callback)
            self.delay = delay
            self.callback = callback
            self.started = False
            self.cancelled = False
            created_timers.append(self)

        def start(self) -> None:
            self.started = True

        def cancel(self) -> None:
            self.cancelled = True

    service = DBDumpService(
        vault_path=vault_path,
        db_path=db_path,
        db_key_hex="ab" * 32,
        device_id="device-1",
        event_store=store,
        timer_factory=_FakeTimer,
    )
    monkeypatch.setattr(service, "maybe_create_dump", lambda: fired.append(1) or None)

    service.schedule_dump_check()
    service.schedule_dump_check()

    assert len(created_timers) == 2
    assert created_timers[0].delay == DB_DUMP_CHECK_DELAY_SECONDS
    assert created_timers[0].started is True
    assert created_timers[0].cancelled is True
    assert created_timers[1].started is True

    created_timers[0].callback()
    assert fired == []

    created_timers[1].callback()
    assert fired == [1]


def test_flush_pending_dump_check_runs_scheduled_dump_synchronously(
    monkeypatch, tmp_path: Path
) -> None:
    vault_path = tmp_path / "vault"
    db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"x" * 1024)
    store = _store(vault_path)
    fired: list[int] = []
    created_timers: list[_FakeTimer] = []

    class _FakeTimer(Timer):
        def __init__(self, delay: float, callback: Callable[[], None]) -> None:
            super().__init__(delay, callback)
            self.delay = delay
            self.callback = callback
            self.started = False
            self.cancelled = False
            created_timers.append(self)

        def start(self) -> None:
            self.started = True

        def cancel(self) -> None:
            self.cancelled = True

    service = DBDumpService(
        vault_path=vault_path,
        db_path=db_path,
        db_key_hex="ab" * 32,
        device_id="device-1",
        event_store=store,
        timer_factory=_FakeTimer,
    )
    monkeypatch.setattr(service, "maybe_create_dump", lambda: fired.append(1) or None)

    service.schedule_dump_check()
    service.flush_pending_dump_check()

    assert len(created_timers) == 1
    assert created_timers[0].started is True
    assert created_timers[0].cancelled is True
    assert fired == [1]

    created_timers[0].callback()
    assert fired == [1]


def test_flush_db_dump_hook_flushes_attached_service(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    app_data_dir = tmp_path / "app"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"x" * 1024)
    store = _store(vault_path)
    engine = create_engine("sqlite:///:memory:")
    session_factory = sessionmaker(bind=engine)
    service = install_db_dump_hook(
        session_factory=session_factory,
        vault_path=vault_path,
        db_path=db_path,
        db_key_hex="ab" * 32,
        app_data_dir=app_data_dir,
        event_store=store,
    )
    calls: list[int] = []
    service.flush_pending_dump_check = lambda: calls.append(1)  # type: ignore[method-assign]

    flush_db_dump_hook(session_factory)

    assert calls == [1]


def test_install_db_dump_hook_schedules_after_commit(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    app_data_dir = tmp_path / "app"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"x" * 1024)
    store = _store(vault_path)
    engine = create_engine("sqlite:///:memory:")
    session_factory = sessionmaker(bind=engine)
    service = install_db_dump_hook(
        session_factory=session_factory,
        vault_path=vault_path,
        db_path=db_path,
        db_key_hex="ab" * 32,
        app_data_dir=app_data_dir,
        event_store=store,
    )
    calls: list[int] = []
    service.schedule_dump_check = lambda: calls.append(1)  # type: ignore[method-assign]

    with session_factory() as session:
        session.commit()

    assert calls == [1]
