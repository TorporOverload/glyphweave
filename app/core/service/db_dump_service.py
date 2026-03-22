from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import sqlcipher3
from sqlalchemy import event

from app.core.device_id import load_device_id, sanitize_device_id
from app.core.sync.event_store import EventStore
from app.core.sync.event_types import EventType
from app.core.sync.hlc import HLCClock, compare_hlc
from app.core.sync.models import HybridLogicalClock, VaultEvent
from app.core.vault_layout import DB_DUMPS_DIR, EVENTS_DIR
from app.utils.logging import logger

DB_DUMP_THRESHOLD_BYTES = 5 * 1024 * 1024
DB_DUMP_MAX_BACKUPS = 3
DB_DUMP_EVENT_TYPE = EventType.DB_DUMP_CREATED


@dataclass(frozen=True)
class DBDumpRecord:
    dump_path: Path
    event_path: Path
    created_at: str
    db_size_bytes: int


def list_db_dump_records(vault_path: Path) -> list[DBDumpRecord]:
    dumps_dir = Path(vault_path) / DB_DUMPS_DIR
    events_dir = Path(vault_path) / EVENTS_DIR / "db_dumps"
    dumps_dir.mkdir(parents=True, exist_ok=True)
    events_dir.mkdir(parents=True, exist_ok=True)

    records: list[DBDumpRecord] = []
    for dump_path in dumps_dir.iterdir():
        if not dump_path.is_file():
            continue
        event_path = events_dir / f"{dump_path.name}.json"
        if not event_path.exists():
            continue
        try:
            payload = json.loads(event_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        records.append(
            DBDumpRecord(
                dump_path=dump_path,
                event_path=event_path,
                created_at=str(payload.get("created_at", "")),
                db_size_bytes=int(payload.get("db_size_bytes", dump_path.stat().st_size)),
            )
        )
    records.sort(key=lambda record: record.created_at)
    return records


def restore_latest_db_dump(
    *,
    vault_path: Path,
    db_path: Path,
    db_key_hex: str,
) -> Path | None:
    """Restore the newest vault DB dump into the local SQLCipher database path."""
    records = list_db_dump_records(vault_path)
    if not records:
        return None

    latest = records[-1]
    db_path.parent.mkdir(parents=True, exist_ok=True)
    source = sqlcipher3.connect(str(latest.dump_path))
    target = sqlcipher3.connect(str(db_path))
    try:
        source.execute(f"PRAGMA key = \"x'{db_key_hex}'\"")
        target.execute(f"PRAGMA key = \"x'{db_key_hex}'\"")
        source.backup(target, pages=256)
        target.commit()
    finally:
        target.close()
        source.close()

    logger.info("Restored local database from dump %s", latest.dump_path)
    return latest.dump_path


class DBDumpService:
    """Maintain rotated encrypted DB dumps inside the vault."""

    def __init__(
        self,
        *,
        vault_path: Path,
        db_path: Path,
        db_key_hex: str,
        device_id: str,
        threshold_bytes: int = DB_DUMP_THRESHOLD_BYTES,
        max_backups: int = DB_DUMP_MAX_BACKUPS,
    ) -> None:
        self._vault_path = Path(vault_path)
        self._db_path = Path(db_path)
        self._db_key_hex = db_key_hex
        self._device_id = sanitize_device_id(device_id)
        self._threshold_bytes = threshold_bytes
        self._max_backups = max_backups
        self._is_dumping = False
        self._clock = HLCClock(device_id=self._device_id)
        self._observe_existing_events()

    @property
    def dumps_dir(self) -> Path:
        path = self._vault_path / DB_DUMPS_DIR
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def events_dir(self) -> Path:
        path = self._vault_path / EVENTS_DIR / "db_dumps"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def maybe_create_dump(self) -> Path | None:
        """Create a new dump if the live DB size has changed by the threshold."""
        if self._is_dumping or not self._db_path.exists():
            return None

        current_size = self._db_path.stat().st_size
        dumps = self._list_dump_records()
        if dumps:
            latest_size = dumps[-1].db_size_bytes
            if abs(current_size - latest_size) < self._threshold_bytes:
                return None

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        dump_name = f"{self._device_id}-{timestamp}-db"
        dump_path = self.dumps_dir / dump_name
        event_path = self.events_dir / f"{dump_name}.json"

        self._is_dumping = True
        try:
            self._backup_database_online(dump_path)
            current_size = self._db_path.stat().st_size
            event_payload = {
                "type": DB_DUMP_EVENT_TYPE,
                "device_id": self._device_id,
                "created_at": timestamp,
                "db_size_bytes": current_size,
                "dump_name": dump_name,
            }
            event_path.write_text(
                json.dumps(event_payload, indent=2),
                encoding="utf-8",
            )
            self._append_event_object(event_payload)
            self._trim_old_dumps()
            logger.info("Created DB dump at %s", dump_path)
            return dump_path
        finally:
            self._is_dumping = False

    def _backup_database_online(self, destination: Path) -> None:
        """Create a consistent encrypted copy using SQLite's online backup API."""
        destination.parent.mkdir(parents=True, exist_ok=True)
        source = sqlcipher3.connect(str(self._db_path))
        target = sqlcipher3.connect(str(destination))
        try:
            source.execute(f"PRAGMA key = \"x'{self._db_key_hex}'\"")
            target.execute(f"PRAGMA key = \"x'{self._db_key_hex}'\"")
            source.backup(target, pages=256)
            target.commit()
        finally:
            target.close()
            source.close()

    def _list_dump_records(self) -> list[DBDumpRecord]:
        return list_db_dump_records(self._vault_path)

    def _trim_old_dumps(self) -> None:
        records = self._list_dump_records()
        overflow = len(records) - self._max_backups
        if overflow <= 0:
            return
        for record in records[:overflow]:
            try:
                record.dump_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Failed to remove old DB dump %s", record.dump_path)
            try:
                record.event_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Failed to remove DB dump event %s", record.event_path)

    def _append_event_object(self, payload: dict[str, object]) -> None:
        store = EventStore(self._vault_path)
        event = VaultEvent(
            event_id=str(uuid.uuid4()),
            type=EventType.DB_DUMP_CREATED,
            device_id=self._device_id,
            hlc=self._next_hlc(),
            payload={key: value for key, value in payload.items() if key != "type"},
            parents=store.read_frontier(self._device_id),
        )
        store.append_event(event)

    def _next_hlc(self) -> HybridLogicalClock:
        wall_time, logical, device_id = self._clock.next()
        return HybridLogicalClock(
            wall_time=wall_time,
            logical=logical,
            device_id=device_id,
        )

    def _observe_existing_events(self) -> None:
        store = EventStore(self._vault_path)
        latest: dict[str, object] | None = None
        for discovered in store.discover_events():
            candidate = discovered.event.hlc.to_dict()
            if latest is None or compare_hlc(candidate, latest) > 0:
                latest = candidate
        if latest is not None:
            self._clock.observe(latest)


def install_db_dump_hook(
    *,
    session_factory,
    vault_path: Path,
    db_path: Path,
    db_key_hex: str,
    app_data_dir: Path,
) -> DBDumpService:
    """Attach a post-commit hook that creates rotated DB dumps."""
    existing = getattr(session_factory, "_glyphweave_db_dump_service", None)
    if existing is not None:
        return existing

    service = DBDumpService(
        vault_path=vault_path,
        db_path=db_path,
        db_key_hex=db_key_hex,
        device_id=load_device_id(app_data_dir),
    )

    @event.listens_for(session_factory, "after_commit")
    def _after_commit(_session) -> None:
        try:
            service.maybe_create_dump()
        except Exception:
            logger.exception("Failed to create DB dump after commit")

    session_factory._glyphweave_db_dump_service = service
    return service
