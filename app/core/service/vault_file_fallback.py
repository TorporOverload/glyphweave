from __future__ import annotations

import mimetypes
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.core.crypto.service.utils import compute_hash
from app.core.runtime_layout import decrypted_files_dir, runtime_cache_dir
from app.core.service.launcher_service import open_with_default_app
from app.core.service.models import OpenFileResult, PendingFallbackOpen, VaultContext
from app.core.service.safe_paths import safe_cache_path
from app.core.vault_layout import resolve_blob_path
from app.utils.file_extensions import ensure_extension_from_mime
from app.utils.logging import logger

if TYPE_CHECKING:
    from app.core.crypto.service.encryption_service import EncryptionService
    from app.core.database.service.file_service import FileService
    from app.core.database.service.folder_service import FolderService


def get_cached_fallback_result(
    context: VaultContext,
    file_ref_id: int,
    file_name: str,
    launch_in_default_app: bool,
) -> OpenFileResult | None:
    """Return a cached fallback open result if one exists and the temp file is still
    present."""
    existing = context.fallback_opens.get(file_ref_id)
    if existing is None:
        return None

    if not existing.temp_path.exists():
        context.fallback_opens.pop(file_ref_id, None)
        return None

    if launch_in_default_app:
        open_with_default_app(existing.temp_path)

    return OpenFileResult(
        opened=True,
        source="fallback",
        file_ref_id=file_ref_id,
        file_name=file_name,
        file_path=existing.temp_path,
        message="Reopened cached decrypted file",
    )


def open_file_fallback(
    context: VaultContext,
    *,
    file_service: "FileService",
    encryption_service: "EncryptionService",
    file_ref: Any,
    launch_in_default_app: bool,
) -> OpenFileResult:
    """Decrypt a vault file to a temporary path and open it as a fallback when FUSE is
    unavailable."""
    vault_path = context.require_vault_path()
    vault_id = context.require_vault_id()
    master_key = context.require_master_key()
    local_data_path = context.local_data_path
    if local_data_path is None:
        raise RuntimeError("Local data path is not set")

    cached = get_cached_fallback_result(
        context,
        file_ref_id=file_ref.id,
        file_name=file_ref.name,
        launch_in_default_app=launch_in_default_app,
    )
    if cached is not None:
        return cached

    file_ref_with_blobs = file_service.get_file_reference_with_blobs(file_ref.id)
    if not file_ref_with_blobs or not file_ref_with_blobs.file_entry:
        raise RuntimeError("File entry not found in database")

    file_entry = file_ref_with_blobs.file_entry
    blob_ids = [b.blob_id for b in file_entry.blobs]
    if not blob_ids:
        raise RuntimeError("No blobs found for file")

    cache_dir = decrypted_files_dir(runtime_cache_dir(local_data_path))
    display_name = ensure_extension_from_mime(file_ref.name, file_entry.mime_type)
    temp_path = safe_cache_path(cache_dir, f"{file_ref.id}_{display_name}")

    try:
        encryption_service.decrypt_file(
            vault_path=vault_path,
            blob_ids=blob_ids,
            output_path=temp_path,
            master_key=master_key.view(),
            vault_id=vault_id.encode("utf-8"),
            file_id=file_entry.file_id,
        )

        context.fallback_opens[file_ref.id] = PendingFallbackOpen(
            file_ref_id=file_ref.id,
            file_name=file_ref.name,
            temp_path=temp_path,
            original_hash=compute_hash(temp_path),
            original_mtime=temp_path.stat().st_mtime,
        )

        if launch_in_default_app:
            open_with_default_app(temp_path)

        return OpenFileResult(
            opened=True,
            source="fallback",
            file_ref_id=file_ref.id,
            file_name=file_ref.name,
            file_path=temp_path,
            message="Decrypted and opened file from cache",
        )
    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        context.fallback_opens.pop(file_ref.id, None)
        raise


def finalize_fallback_open(
    context: VaultContext,
    *,
    file_service: "FileService",
    folder_service: "FolderService",
    encryption_service: "EncryptionService",
    file_ref_id: int,
) -> str:
    """Save any changes from a fallback-opened temp file back to the vault and clean
    up."""
    pending = context.fallback_opens.get(file_ref_id)
    if pending is None:
        raise FileNotFoundError("File is no longer unlocked")

    temp_path = pending.temp_path
    try:
        if not temp_path.exists():
            return "Cached file was removed. Nothing to save"

        current_mtime = temp_path.stat().st_mtime
        current_hash = compute_hash(temp_path)
        has_changes = (
            current_hash != pending.original_hash
            or current_mtime != pending.original_mtime
        )

        if has_changes:
            file_ref = file_service.get_file_reference_with_blobs(file_ref_id)
            if not file_ref or not file_ref.file_entry:
                raise RuntimeError("Could not find vault file entry to save changes")
            re_encrypt_file(
                context,
                file_service=file_service,
                folder_service=folder_service,
                encryption_service=encryption_service,
                file_ref=file_ref,
                plaintext_path=temp_path,
            )
            return "Changes saved to vault and file unmounted"

        return "No changes detected. File unmounted"
    finally:
        context.fallback_opens.pop(file_ref_id, None)
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


def re_encrypt_file(
    context: VaultContext,
    *,
    file_service: "FileService",
    folder_service: "FolderService",
    encryption_service: "EncryptionService",
    file_ref: Any,
    plaintext_path: Path,
) -> None:
    """Re-encrypt a modified plaintext file and update the vault database entry."""
    vault_path = context.require_vault_path()
    vault_id = context.require_vault_id()
    master_key = context.require_master_key()

    original_size = plaintext_path.stat().st_size
    content_hash = compute_hash(plaintext_path)
    blob_ids: list[str] = []
    new_entry_created = False

    existing_entry = file_service.find_by_content_hash(content_hash)
    if existing_entry is not None:
        old_entry_id = file_service.update_file_reference_entry(
            file_ref.id,
            existing_entry.id,
        )
        if old_entry_id is not None and old_entry_id != existing_entry.id:
            _cleanup_orphaned_entry(folder_service, old_entry_id)
        return

    new_file_id = str(uuid.uuid4())
    try:
        blob_ids = encryption_service.encrypt_file(
            file_path=plaintext_path,
            vault_path=vault_path,
            master_key=master_key.view(),
            vault_id=vault_id.encode("utf-8"),
            file_id=new_file_id,
        )

        encrypted_size = sum(
            resolve_blob_path(vault_path, bid).stat().st_size for bid in blob_ids
        )
        mime_type, _ = mimetypes.guess_type(file_ref.name)
        mime_type = mime_type or "application/octet-stream"

        new_entry = file_service.create_file_entry_with_blobs(
            file_id=new_file_id,
            content_hash=content_hash,
            mime_type=mime_type,
            encrypted_size=encrypted_size,
            original_size=original_size,
            blob_ids=blob_ids,
        )
        new_entry_created = True

        old_entry_id = file_service.update_file_reference_entry(
            file_ref.id, new_entry.id
        )
        if old_entry_id is not None:
            _cleanup_orphaned_entry(folder_service, old_entry_id)
    except Exception:
        if blob_ids and not new_entry_created:
            _cleanup_partial_blobs(vault_path, blob_ids)
        raise


def _cleanup_orphaned_entry(folder_service: "FolderService", entry_id: int) -> None:
    """Run garbage collection on a file entry that no longer has any references."""
    try:
        folder_service.gc.cleanup_orphaned_entry(entry_id)
    except Exception as e:
        logger.warning(f"GC cleanup failed (non-fatal): {e}")


def _cleanup_partial_blobs(vault_path: Path, blob_ids: list[str]) -> None:
    """Delete partially written blob files from the vault on error."""
    for blob_id in blob_ids:
        blob_path = resolve_blob_path(vault_path, blob_id)
        try:
            if blob_path.exists():
                blob_path.unlink()
        except OSError:
            pass
