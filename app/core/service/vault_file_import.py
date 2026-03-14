from __future__ import annotations

import mimetypes
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from app.core.crypto.service.utils import compute_hash
from app.core.service.models import AddFileResult, VaultContext
from app.core.vault_layout import resolve_blob_path

if TYPE_CHECKING:
    from app.core.crypto.service.encryption_service import EncryptionService
    from app.core.database.service.file_service import FileService
    from app.core.database.service.folder_service import FolderService


def add_file(
    context: VaultContext,
    *,
    file_service: "FileService",
    folder_service: "FolderService | None" = None,
    encryption_service: "EncryptionService",
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
    )
    destination_name = dest_name or source.name
    content_hash = compute_hash(source)
    existing_entry = file_service.find_by_content_hash(content_hash)
    if existing_entry is not None:
        file_service.create_file_reference(
            name=destination_name,
            parent_id=parent_id,
            file_entry_id=existing_entry.id,
        )
        return AddFileResult(
            file_name=destination_name,
            deduplicated=True,
            file_id=None,
            original_size=existing_entry.original_size_bytes,
            encrypted_size=existing_entry.encrypted_size_bytes,
            blob_count=0,
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

        file_entry = file_service.create_file_entry_with_blobs(
            file_id=file_id,
            content_hash=content_hash,
            mime_type=mime_type,
            encrypted_size=encrypted_size,
            original_size=original_size,
            blob_ids=blob_ids,
        )
        file_entry_created = True
        file_service.create_file_reference(
            name=destination_name,
            parent_id=parent_id,
            file_entry_id=file_entry.id,
        )

        return AddFileResult(
            file_name=destination_name,
            deduplicated=False,
            file_id=file_id,
            original_size=original_size,
            encrypted_size=encrypted_size,
            blob_count=len(blob_ids),
        )
    except Exception:
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


def _normalize_vault_dir_path(path: str | None) -> str:
    """Normalize a virtual directory path for vault storage."""
    if path is None:
        return "/"

    normalized = path.strip().replace("\\", "/")
    if not normalized:
        return "/"

    parts = [segment for segment in normalized.split("/") if segment not in {"", "."}]
    if any(segment == ".." for segment in parts):
        raise ValueError("Parent traversal ('..') is not allowed in destination path")

    if not parts:
        return "/"
    return "/" + "/".join(parts)


def _resolve_or_create_parent_folder(
    folder_service: "FolderService | None",
    dest_parent_virtual_path: str | None,
) -> int | None:
    """Resolve or create the parent folder for a given virtual path. 
    Parents will be created as needed. 
    Returns the parent folder ID, or None for root."""
    parent_virtual_path = _normalize_vault_dir_path(dest_parent_virtual_path)
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
        elif not existing.is_folder:
            bad_path = "/" + "/".join(traversed)
            raise NotADirectoryError(
                f"Destination path segment is not a folder: {bad_path}"
            )

        parent_id = existing.id

    return parent_id
