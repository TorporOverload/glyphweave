from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.service.file_service import FileService
from app.infrastructure.persistence.db.service.folder_service import FolderService


def _build_services(tmp_path):
    db_path = tmp_path / "file_service.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)

    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return FileService(session_factory), FolderService(session_factory, tmp_path)


def test_create_file_reference_uses_parent_virtual_path(tmp_path) -> None:
    file_service, folder_service = _build_services(tmp_path)
    imports = folder_service.create_folder("Imports", None)

    file_entry = file_service.create_file_entry_with_blobs(
        file_id="f-1",
        content_hash="h-1",
        mime_type="application/pdf",
        encrypted_size=10,
        original_size=9,
        blob_ids=["b-1.enc"],
    )

    created = file_service.create_file_reference(
        name="001.pdf",
        parent_id=imports.id,
        file_entry_id=file_entry.id,
    )

    assert created.virtual_path == "/Imports/001.pdf"
    assert created.node_id


def test_create_empty_file_uses_parent_virtual_path(tmp_path) -> None:
    file_service, folder_service = _build_services(tmp_path)
    imports = folder_service.create_folder("Imports", None)

    created = file_service.create_empty_file("new.txt", parent_id=imports.id)

    assert created.virtual_path == "/Imports/new.txt"
    assert created.node_id


def test_node_id_survives_rename_and_move(tmp_path) -> None:
    file_service, folder_service = _build_services(tmp_path)
    source = folder_service.create_folder("Source", None)
    target = folder_service.create_folder("Target", None)
    file_entry = file_service.create_file_entry_with_blobs(
        file_id="f-2",
        content_hash="h-2",
        mime_type="text/plain",
        encrypted_size=12,
        original_size=11,
        blob_ids=["b-2.enc"],
    )
    created = file_service.create_file_reference(
        name="draft.txt",
        parent_id=source.id,
        file_entry_id=file_entry.id,
    )

    original_node_id = created.node_id

    folder_service.rename_entry(created.id, "final.txt", target.id)
    moved = folder_service.get_by_id(created.id)

    assert moved is not None
    assert moved.node_id == original_node_id
    assert moved.virtual_path == "/Target/final.txt"


def test_file_reference_schema_defines_unique_node_id_index(tmp_path) -> None:
    db_path = tmp_path / "legacy_file_service.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)

    indexes = {
        index["name"]: index for index in inspect(engine).get_indexes("file_reference")
    }

    assert "ix_file_reference_node_id" in indexes
    assert bool(indexes["ix_file_reference_node_id"]["unique"]) is True
