from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database.base import Base
from app.core.database.service.file_service import FileService
from app.core.database.service.folder_service import FolderService


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


def test_create_empty_file_uses_parent_virtual_path(tmp_path) -> None:
    file_service, folder_service = _build_services(tmp_path)
    imports = folder_service.create_folder("Imports", None)

    created = file_service.create_empty_file("new.txt", parent_id=imports.id)

    assert created.virtual_path == "/Imports/new.txt"
