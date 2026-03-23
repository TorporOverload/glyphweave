from __future__ import annotations

from pathlib import Path

import sqlcipher3
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.common.config import get_vaults_data_dir
from app.infrastructure.persistence.db.base_model import Base
from app.common.logging import logger

DB_FILENAME = "vault.db"

from app.infrastructure.persistence.db.model import search_index  # noqa: F401, E402
from app.infrastructure.persistence.db.model.file_blob_reference import (  # noqa: F401, E402
    FileBlobReference,
)
from app.infrastructure.persistence.db.model.file_entry import FileEntry  # noqa: F401, E402
from app.infrastructure.persistence.db.model.file_reference import (  # noqa: F401, E402
    FileReference,
)
from app.infrastructure.persistence.db.model.processed_event import (  # noqa: F401, E402
    ProcessedEvent,
)
from app.infrastructure.persistence.db.model.sync_node_state import (  # noqa: F401, E402
    SyncNodeState,
)
from app.infrastructure.persistence.db.model.sync_tombstone import (  # noqa: F401, E402
    SyncTombstone,
)
from app.infrastructure.persistence.db.model.WAL_entry import WalEntry  # noqa: F401, E402


class DbBase:
    """SQLCipher configuration."""

    def __init__(
        self,
        vault_id: str,
        db_key: str,
        vaults_data_dir: Path | None = None,
    ):
        self.db_key = db_key
        self.vaults_data_dir = Path(vaults_data_dir or get_vaults_data_dir())
        self.db_path = self.resolve_db_path(vault_id, self.vaults_data_dir)
        self.engine = self.create_db_engine(self.db_path)

        # Set up event listener to apply PRAGMA key on every connection
        @event.listens_for(self.engine, "connect")
        def _set_pragma_key(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            pragma_sql = f"PRAGMA key = \"x'{self.db_key}'\""
            cursor.execute(pragma_sql)
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.close()

        self.SessionLocal = sessionmaker(
            bind=self.engine, autoflush=False, autocommit=False
        )

        try:
            # Register FTS5 triggers and views
            from app.infrastructure.persistence.db.model.search_index import (
                register_ddl_listeners,
            )

            register_ddl_listeners()

            # Create all tables with explicit connection and commit
            with self.engine.begin() as conn:
                Base.metadata.create_all(bind=conn)
                logger.info(f"Database initialized for vault {vault_id}")
        except Exception as e:
            logger.error(f"Error creating database tables: {e}")
            raise

    @staticmethod
    def resolve_db_path(vault_id: str, vaults_data_dir: Path) -> Path:
        """Return the filesystem path for the vault database."""
        db_dir = vaults_data_dir / vault_id
        db_dir.mkdir(parents=True, exist_ok=True)
        return db_dir / DB_FILENAME

    @staticmethod
    def create_db_engine(db_path: Path):
        """Create and return a SQLCipher engine for the given vault DB path."""
        db_path_str = str(db_path)

        engine = create_engine(
            f"sqlite:///{db_path_str}",
            module=sqlcipher3,
            future=True,
            connect_args={"check_same_thread": False},
        )

        return engine

    def get_session(self):
        """Return a new database session."""
        return self.SessionLocal()
