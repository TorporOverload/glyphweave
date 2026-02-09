from __future__ import annotations

from pathlib import Path

import sqlcipher3
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import GLYPHWEAVE_LOCAL_DIR
from app.utils.logging import logger

DB_FILENAME = "glyphweave.db"

engine = None


class Base(DeclarativeBase):
    pass


from app.core.database.model import search_index  # noqa: F401, E402
from app.core.database.model.file_blob_reference import FileBlobReference  # noqa: F401, E402
from app.core.database.model.file_entry import FileEntry  # noqa: F401, E402
from app.core.database.model.file_reference import FileReference  # noqa: F401, E402
from app.core.database.model.WAL_entry import WalEntry  # noqa: F401, E402


class DbBase:
    """SQLCipher configuration."""
    def __init__(self, vault_id: str, db_key: str):
        self.db_key = db_key
        self.engine = self.create_db_engine(vault_id)

        # Set up event listener to apply PRAGMA key on every connection
        @event.listens_for(self.engine, "connect")
        def _set_pragma_key(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute(f"PRAGMA key = \"x'{self.db_key}'\"")
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.close()

        self.SessionLocal = sessionmaker(
            bind=self.engine, autoflush=False, autocommit=False
        )

        try:
            # Register FTS5 triggers and views
            from app.core.database.model.search_index import register_ddl_listeners

            register_ddl_listeners()

            # Create all tables with explicit connection and commit
            with self.engine.begin() as conn:
                Base.metadata.create_all(bind=conn)
                logger.info(f"Database initialized for vault {vault_id}")
        except Exception as e:
            logger.error(f"Error creating database tables: {e}")
            raise

    @staticmethod
    def create_db_engine(vault_id: str):
        vault_dir = Path(GLYPHWEAVE_LOCAL_DIR) / vault_id
        vault_dir.mkdir(parents=True, exist_ok=True)
        db_path = str(vault_dir / DB_FILENAME)

        engine = create_engine(
            f"sqlite:///{db_path}",
            module=sqlcipher3,
            future=True,
            connect_args={"check_same_thread": False},
        )

        return engine

    def get_session(self):
        return self.SessionLocal()
