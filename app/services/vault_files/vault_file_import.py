from __future__ import annotations

import mimetypes
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, cast

from sqlalchemy.exc import IntegrityError

from app.infrastructure.crypto.service.utils import compute_hash
from app.infrastructure.persistence.db.model.extraction_status import ExtractionStatus
from app.services.content.indexing_service import IndexingService
from app.services.models import AddFileResult, VaultContext
from app.common.paths.vault_layout import resolve_blob_path
from app.common.logging import logger
from app.services.vault_files.helpers import normalize_vault_path

if TYPE_CHECKING:
    from app.infrastructure.crypto.service.encryption_service import EncryptionService
    from app.infrastructure.persistence.db.service.file_service import FileService
    from app.infrastructure.persistence.db.service.folder_service import FolderService
    from app.services.sync.event_emitter import EventEmitter, FileRefLike, FolderRefLike


def add_file(
    context: VaultContext,
    *,
    file_service: "FileService",
    folder_service: "FolderService | None" = None,
    encryption_service: "EncryptionService",
    indexing_service: "IndexingService | None" = None,
    event_emitter: "EventEmitter | None" = None,
    source: Path,
    dest_name: str | None = None,
    dest_parent_virtual_path: str | None = None,
) -> AddFileResult:
    """Add a file to the vault, handling encryption,
    deduplication, and folder placement."""

    vault_path = context.require_vault_path()
    vault_id = context.require_vault_id()
    master_key = context.require_master_key()

    if not source.exists() or not source.is_file():
        raise FileNotFoundError(f"File not found: {source}")

    parent_id = _resolve_or_create_parent_folder(
        folder_service,
        dest_parent_virtual_path,
        event_emitter=event_emitter,
    )
    destination_name = dest_name or source.name
    logger.info(f"Import started: source={source}, destination={destination_name}")
    content_hash = compute_hash(source)
    existing_entry = file_service.find_by_content_hash(content_hash)
    if existing_entry is not None:
        logger.info(
            f"Import deduplicated: destination={destination_name}, "
            f"existing_entry_id={existing_entry.id}"
        )
        created_ref = file_service.create_file_reference(
            name=destination_name,
            parent_id=parent_id,
            file_entry_id=existing_entry.id,
        )
        if event_emitter is not None:
            event_emitter.emit_file_add(cast("FileRefLike", created_ref))
        return AddFileResult(
            file_name=destination_name,
            deduplicated=True,
            file_id=None,
            original_size=existing_entry.original_size_bytes,
            encrypted_size=existing_entry.encrypted_size_bytes,
            blob_count=0,
            indexed=(
                getattr(existing_entry, "text_extraction_status", None)
                == ExtractionStatus.DONE.value
            ),
        )

    blob_ids: list[str] = []
    file_entry_created = False
    file_id = str(uuid.uuid4())
    try:
        original_size = source.stat().st_size
        blob_ids = encryption_service.encrypt_file(
            file_path=source,
            vault_path=vault_path,
            master_key=master_key.view(),
            vault_id=vault_id.encode("utf-8"),
            file_id=file_id,
        )
        encrypted_size = sum(
            resolve_blob_path(vault_path, bid).stat().st_size for bid in blob_ids
        )

        mime_type, _ = mimetypes.guess_type(source.name)
        mime_type = mime_type or "application/octet-stream"

        try:
            file_entry = file_service.create_file_entry_with_blobs(
                file_id=file_id,
                content_hash=content_hash,
                mime_type=mime_type,
                encrypted_size=encrypted_size,
                original_size=original_size,
                blob_ids=blob_ids,
            )
        except IntegrityError:
            # Another thread won the race for this content_hash.
            # Clean up our redundant blobs and reuse the winning entry.
            _cleanup_partial_blobs(vault_path, blob_ids)
            blob_ids = []
            existing_entry = file_service.find_by_content_hash(content_hash)
            if existing_entry is None:
                raise
            logger.info(
                f"Import deduplicated (concurrent): destination={destination_name}, "
                f"existing_entry_id={existing_entry.id}"
            )
            created_ref = file_service.create_file_reference(
                name=destination_name,
                parent_id=parent_id,
                file_entry_id=existing_entry.id,
            )
            if event_emitter is not None:
                event_emitter.emit_file_add(cast("FileRefLike", created_ref))
            return AddFileResult(
                file_name=destination_name,
                deduplicated=True,
                file_id=None,
                original_size=existing_entry.original_size_bytes,
                encrypted_size=existing_entry.encrypted_size_bytes,
                blob_count=0,
                indexed=(
                    getattr(existing_entry, "text_extraction_status", None)
                    == ExtractionStatus.DONE.value
                ),
            )
        file_entry_created = True
        logger.info(
            f"Import encrypted and stored: destination={destination_name}, "
            f"entry_id={file_entry.id}, file_id={file_id}, blobs={len(blob_ids)}"
        )
        created_ref = file_service.create_file_reference(
            name=destination_name,
            parent_id=parent_id,
            file_entry_id=file_entry.id,
        )
        if event_emitter is not None:
            event_emitter.emit_file_add(cast("FileRefLike", created_ref))

        indexed = False
        if indexing_service is not None:
            logger.info(
                f"Import triggering indexing: destination={destination_name}, "
                f"entry_id={file_entry.id}"
            )
            indexed = indexing_service.index_source_file(
                file_entry.id,
                source,
                destination_name,
            )
            logger.info(
                f"Import indexing result: destination={destination_name}, "
                f"entry_id={file_entry.id}, indexed={indexed}"
            )

        return AddFileResult(
            file_name=destination_name,
            deduplicated=False,
            file_id=file_id,
            original_size=original_size,
            encrypted_size=encrypted_size,
            blob_count=len(blob_ids),
            indexed=indexed,
        )
    except Exception:
        logger.exception(
            f"Import failed: source={source}, destination={destination_name}"
        )
        if blob_ids and not file_entry_created:
            _cleanup_partial_blobs(vault_path, blob_ids)
        raise


def _cleanup_partial_blobs(vault_path: Path, blob_ids: list[str]) -> None:
    """Clean up orphan data if the blob was created but the file entry was not"""
    for blob_id in blob_ids:
        blob_path = resolve_blob_path(vault_path, blob_id)
        try:
            if blob_path.exists():
                blob_path.unlink()
        except OSError:
            pass
def _resolve_or_create_parent_folder(
    folder_service: "FolderService | None",
    dest_parent_virtual_path: str | None,
    event_emitter: "EventEmitter | None" = None,
) -> int | None:
    """Resolve or create the parent folder for a given virtual path.
    Parents will be created as needed.
    Returns the parent folder ID, or None for root."""
    parent_virtual_path = normalize_vault_path(dest_parent_virtual_path)
    if parent_virtual_path == "/":
        return None

    if folder_service is None:
        raise RuntimeError("Folder service is required for non-root destination path")

    parent_id: int | None = None
    traversed: list[str] = []
    for segment in parent_virtual_path.strip("/").split("/"):
        traversed.append(segment)
        existing = folder_service.get_child_by_name(parent_id, segment)

        if existing is None:
            existing = folder_service.create_folder(name=segment, parent_id=parent_id)
            if event_emitter is not None:
                event_emitter.emit_folder_create(cast("FolderRefLike", existing))
        elif not existing.is_folder:
            bad_path = "/" + "/".join(traversed)
            raise NotADirectoryError(
                f"Destination path segment is not a folder: {bad_path}"
            )

        parent_id = existing.id

    return parent_id
