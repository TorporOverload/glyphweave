import json

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.database.base import Base
from app.core.database.model.file_reference import FileReference
from app.core.sync.event_emitter import EventEmitter
from app.core.sync.replay import replay_vault_events


class _Blob:
    def __init__(self, blob_id: str) -> None:
        self.blob_id = blob_id


class _FileEntry:
    def __init__(self) -> None:
        self.file_id = "file-1"
        self.blobs = [_Blob("blob-1.enc")]
        self.content_hash = "hash-1"
        self.mime_type = "text/plain"
        self.original_size_bytes = 5
        self.encrypted_size_bytes = 11
        self.metadata_json = None


class _Ref:
    def __init__(self, *, name: str, node_id: str, parent=None, file_entry=None, is_folder=False) -> None:
        self.name = name
        self.node_id = node_id
        self.parent = parent
        self.file_entry = file_entry
        self.is_folder = is_folder


def test_replay_round_trip_from_emitted_events(tmp_path) -> None:
    app_data_dir = tmp_path / "app"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    (app_data_dir / "device.json").write_text(
        json.dumps({"device_id": "device-a", "name": "A", "status": "active"}),
        encoding="utf-8",
    )
    vault_path = tmp_path / "vault"
    emitter = EventEmitter(vault_path=vault_path, app_data_dir=app_data_dir)

    folder = _Ref(name="docs", node_id="folder-1", is_folder=True)
    file_ref = _Ref(
        name="report.txt",
        node_id="file-1",
        parent=folder,
        file_entry=_FileEntry(),
    )
    emitter.emit_folder_create(folder)
    emitter.emit_file_add(file_ref)

    engine = create_engine(f"sqlite:///{tmp_path / 'replay_round_trip.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    result = replay_vault_events(session_factory=session_factory, vault_path=vault_path)

    assert result.total == 2
    assert result.failed == 0
    with session_factory() as session:
        refs = session.scalars(
            select(FileReference).order_by(FileReference.virtual_path)
        ).all()
        assert [ref.virtual_path for ref in refs] == ["/docs", "/docs/report.txt"]
