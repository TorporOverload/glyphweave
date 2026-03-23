from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import joinedload

from app.common.logging import logger
from app.infrastructure.persistence.db.model.file_entry import FileEntry
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.service.session import session_scope


def create_empty_file(service, name: str, parent_id: Optional[int]) -> FileReference:
    with session_scope(service._session_factory) as session:
        service._validate_entry_name(name)
        time_now = datetime.now(timezone.utc)
        file_id = secrets.token_hex(16)

        parent_ref = None
        if parent_id is not None:
            parent_ref = session.get(FileReference, parent_id)
            if parent_ref is None:
                raise FileNotFoundError(f"Parent folder {parent_id} not found")
            if not parent_ref.is_folder:
                raise NotADirectoryError(
                    f"Parent reference {parent_id} is not a folder"
                )

        existing = session.scalars(
            select(FileReference).where(
                FileReference.parent_id == parent_id,
                FileReference.name == name,
            )
        ).first()
        if existing is not None:
            raise FileExistsError(
                f"An entry named '{name}' already exists in the destination"
            )

        empty_entry = FileEntry(
            file_id=file_id,
            content_hash=hashlib.sha256(file_id.encode()).hexdigest(),
            mime_type="application/octet-stream",
            encrypted_size_bytes=0,
            original_size_bytes=0,
            created_at=time_now,
            updated_at=time_now,
        )
        session.add(empty_entry)
        session.flush()

        file_ref = FileReference(
            name=name,
            parent=parent_ref,
            is_folder=False,
            file_entry_id=empty_entry.id,
        )
        session.add(file_ref)
        session.flush()

        result = (
            session.scalars(
                select(FileReference)
                .options(
                    joinedload(FileReference.file_entry).joinedload(FileEntry.blobs)
                )
                .where(FileReference.id == file_ref.id)
            )
            .unique()
            .first()
        )
        if result is None:
            raise RuntimeError(
                "Unexpected: created empty FileReference could not be re-fetched "
                f"(id={file_ref.id})"
            )

        logger.info(
            "Created new empty file '%s' (ref_id=%s, entry_id=%s)",
            name,
            result.id,
            empty_entry.id,
        )
        return result
