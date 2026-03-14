from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.service.models import UnlockedFileInfo, VaultContext
from app.core.service.vault_file_fallback import finalize_fallback_open
from app.core.service.vault_file_mounts import list_mounted_unlocked_files
from app.utils.logging import logger

if TYPE_CHECKING:
    from app.core.crypto.service.encryption_service import EncryptionService
    from app.core.database.service.file_service import FileService
    from app.core.database.service.folder_service import FolderService


def list_fallback_unlocked_files(context: VaultContext) -> list[UnlockedFileInfo]:
    """Return info for all files currently open via the fallback decryption cache."""
    return [
        UnlockedFileInfo(
            source="fallback",
            file_ref_id=info.file_ref_id,
            file_name=info.file_name,
            file_path=info.temp_path,
            opened_at=info.opened_at,
        )
        for info in context.fallback_opens.values()
    ]


def list_unlocked_files(context: VaultContext) -> list[UnlockedFileInfo]:
    """Return all unlocked files from both FUSE mounts and fallback cache, sorted by
    open time."""
    unlocked_items = list_mounted_unlocked_files(context)
    unlocked_items.extend(list_fallback_unlocked_files(context))
    unlocked_items.sort(key=lambda item: item.opened_at)
    return unlocked_items


def cleanup_unlocked_files(
    context: VaultContext,
    *,
    file_service: "FileService",
    folder_service: "FolderService",
    encryption_service: "EncryptionService",
) -> None:
    """Finalize all fallback-open files, unmount FUSE mounts, and dispose the database
    engine."""
    for file_ref_id in list(context.fallback_opens.keys()):
        try:
            finalize_fallback_open(
                context,
                file_service=file_service,
                folder_service=folder_service,
                encryption_service=encryption_service,
                file_ref_id=file_ref_id,
            )
        except Exception as e:
            logger.warning(f"Failed cleanup for fallback file {file_ref_id}: {e}")

    mounts = context.mounts
    if mounts:
        mounts.cleanup_all()

    if context.db and context.db.engine:
        context.db.engine.dispose()
