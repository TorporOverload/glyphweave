import json

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.database.base import Base
from app.core.database.model.processed_event import ProcessedEvent
from app.core.service.db_dump_service import DBDumpService
from app.core.sync.event_types import EventType
from app.core.sync.replay import replay_vault_events


def test_db_dump_event_is_discoverable_and_replayable(monkeypatch, tmp_path) -> None:
    app_data_dir = tmp_path / "app"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    vault_path = tmp_path / "vault"
    db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"x" * 1024)

    service = DBDumpService(
        vault_path=vault_path,
        db_path=db_path,
        db_key_hex="ab" * 32,
        device_id="device-a",
    )
    monkeypatch.setattr(
        service,
        "_backup_database_online",
        lambda destination: destination.write_bytes(b"dump"),
    )

    dump_path = service.maybe_create_dump()
    assert dump_path is not None

    engine = create_engine(f"sqlite:///{tmp_path / 'db_dump_replay.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result = replay_vault_events(session_factory=session_factory, vault_path=vault_path)

    assert result.total >= 1
    with session_factory() as session:
        processed = session.scalars(
            select(ProcessedEvent).where(ProcessedEvent.event_type == EventType.DB_DUMP_CREATED.value)
        ).all()
        assert len(processed) == 1
