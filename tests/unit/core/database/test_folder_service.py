from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.service.folder_service import FolderService


def test_create_folder_builds_nested_virtual_path(tmp_path) -> None:
    db_path = tmp_path / "folder_service.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)

    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    service = FolderService(session_factory, tmp_path)

    docs = service.create_folder("docs", None)
    reports = service.create_folder("reports", docs.id)
    year = service.create_folder("2026", reports.id)

    assert docs.virtual_path == "/docs"
    assert reports.virtual_path == "/docs/reports"
    assert year.virtual_path == "/docs/reports/2026"
