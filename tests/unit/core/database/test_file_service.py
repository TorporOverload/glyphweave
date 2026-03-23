from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.service.file_service import FileService
from app.infrastructure.persistence.db.service.folder_service import FolderService
from app.infrastructure.persistence.db.service.session import session_scope
from app.infrastructure.persistence.db.service.sync_bootstrap import bootstrap_file_reference_node_ids


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


def test_sync_bootstrap_backfills_missing_node_ids(tmp_path) -> None:
    db_path = tmp_path / "legacy_file_service.db"
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE file_entry (
                    id INTEGER PRIMARY KEY,
                    file_id VARCHAR NOT NULL UNIQUE,
                    content_hash VARCHAR NOT NULL UNIQUE,
                    mime_type VARCHAR NOT NULL,
                    encrypted_size_bytes INTEGER NOT NULL,
                    original_size_bytes INTEGER NOT NULL,
                    text_extraction_status VARCHAR,
                    extracted_text_preview TEXT,
                    metadata_json TEXT,
                    created_at DATETIME,
                    updated_at DATETIME
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE file_reference (
                    id INTEGER PRIMARY KEY,
                    parent_id INTEGER,
                    name VARCHAR NOT NULL,
                    is_folder BOOLEAN NOT NULL DEFAULT 0,
                    virtual_path VARCHAR NOT NULL UNIQUE,
                    added_at DATETIME,
                    modified_at DATETIME,
                    accessed_at DATETIME,
                    file_entry_id INTEGER
                )
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT INTO file_reference (
                    id, parent_id, name, is_folder, virtual_path,
                    added_at, modified_at, accessed_at, file_entry_id
                )
                VALUES (1, NULL, 'docs', 1, '/docs', NULL, NULL, NULL, NULL)
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT INTO file_reference (
                    id, parent_id, name, is_folder, virtual_path,
                    added_at, modified_at, accessed_at, file_entry_id
                )
                VALUES (2, 1, 'report.txt', 0, '/docs/report.txt', NULL, NULL, NULL, NULL)
                """
            )
        )

    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    updated = bootstrap_file_reference_node_ids(session_factory)

    assert updated == 2

    with session_scope(session_factory, commit=False) as session:
        refs = session.query(FileReference).order_by(FileReference.id).all()

    assert len(refs) == 2
    assert refs[0].node_id
    assert refs[1].node_id
    assert refs[0].node_id != refs[1].node_id
