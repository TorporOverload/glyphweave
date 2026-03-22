from __future__ import annotations

import uuid

from sqlalchemy import Index, inspect, or_, select, text
from sqlalchemy.orm import sessionmaker

from app.core.database.model.file_reference import FileReference
from app.core.database.service.session import session_scope


def bootstrap_file_reference_node_ids(session_factory: sessionmaker) -> int:
    """Bootstrap stable node IDs for the file_reference table."""
    _bootstrap_node_id_column(session_factory)

    updated = 0
    with session_scope(session_factory) as session:
        refs = session.scalars(
            select(FileReference).where(
                or_(
                    FileReference.node_id.is_(None),
                    FileReference.node_id == "",
                )
            )
        ).all()

        for ref in refs:
            ref.node_id = str(uuid.uuid4())
            updated += 1

    _bootstrap_node_id_index(session_factory)
    return updated


def _bootstrap_node_id_column(session_factory: sessionmaker) -> None:
    with session_scope(session_factory) as session:
        bind = session.get_bind()
        if bind is None:
            raise RuntimeError("Database bind is not available")

        columns = inspect(bind).get_columns("file_reference")
        column_names = {str(column["name"]) for column in columns}
        if "node_id" in column_names:
            return

        session.execute(text("ALTER TABLE file_reference ADD COLUMN node_id VARCHAR"))


def _bootstrap_node_id_index(session_factory: sessionmaker) -> None:
    with session_scope(session_factory) as session:
        bind = session.get_bind()
        if bind is None:
            raise RuntimeError("Database bind is not available")

        Index(
            "ix_file_reference_node_id",
            FileReference.__table__.c.node_id,
            unique=True,
            sqlite_where=FileReference.__table__.c.node_id.is_not(None),
        ).create(
            bind=bind,
            checkfirst=True,
        )
