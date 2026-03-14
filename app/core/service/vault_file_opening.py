from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.service.models import OpenFileResult, VaultContext
from app.core.service.vault_file_fallback import (
    get_cached_fallback_result,
    open_file_fallback,
)
from app.core.service.vault_file_mounts import (
    get_mounted_open_result,
    mount_file,
)

if TYPE_CHECKING:
    from app.core.crypto.service.encryption_service import EncryptionService
    from app.core.database.service.file_service import FileService


def open_file_by_ref(
    context: VaultContext,
    *,
    file_service: "FileService",
    encryption_service: "EncryptionService",
    file_ref_id: int,
    launch_in_default_app: bool,
) -> OpenFileResult:
    """Open a vault file by reference ID, preferring FUSE mount over fallback
    decryption."""
    file_ref = file_service.get_file_reference_with_blobs(file_ref_id)
    if not file_ref or file_ref.is_folder:
        raise FileNotFoundError(f"File reference not found: {file_ref_id}")

    mounted = get_mounted_open_result(
        context,
        file_ref=file_ref,
        launch_in_default_app=launch_in_default_app,
    )
    if mounted is not None:
        return mounted

    cached = get_cached_fallback_result(
        context,
        file_ref_id=file_ref.id,
        file_name=file_ref.name,
        launch_in_default_app=launch_in_default_app,
    )
    if cached is not None:
        return cached

    mounted = mount_file(
        context,
        file_ref=file_ref,
        launch_in_default_app=launch_in_default_app,
    )
    if mounted is not None:
        return mounted

    return open_file_fallback(
        context,
        file_service=file_service,
        encryption_service=encryption_service,
        file_ref=file_ref,
        launch_in_default_app=launch_in_default_app,
    )
