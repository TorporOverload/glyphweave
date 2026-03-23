from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.event_store import EventStore
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import HybridLogicalClock, VaultEvent
from app.services.sync.replay import replay_vault_events


def test_replay_archives_late_file_add_after_folder_delete(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    store = EventStore(vault_path)
    events = [
        VaultEvent(
            event_id="evt-folder-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=1000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-1", "parent_node_id": None, "name": "docs"},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-folder-delete",
            type=EventType.FOLDER_DELETE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=2000, logical=0, device_id="device-a"),
            payload={"node_id": "folder-1", "cascade": True},
            parents=[],
        ),
        VaultEvent(
            event_id="evt-late-file",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=3000, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-1",
                "file_id": "content-1",
                "parent_node_id": "folder-1",
                "name": "report.txt",
                "blob_ids": ["blob-1.enc"],
                "content_hash": "content-hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 11,
                "metadata_json": None,
            },
            parents=[],
        ),
    ]
    for event in events:
        store.append_event(event)

    engine = create_engine(f"sqlite:///{tmp_path / 'conflict.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result = replay_vault_events(session_factory=session_factory, vault_path=vault_path)

    assert result.conflicts == 1
    with session_factory() as session:
        conflict_folder = session.scalar(
            select(FileReference).where(FileReference.name == ".glyphweave_conflicts")
        )
        archived = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        assert conflict_folder is not None
        assert archived is not None
        assert archived.parent_id == conflict_folder.id
        assert archived.virtual_path.startswith("/.glyphweave_conflicts/")
