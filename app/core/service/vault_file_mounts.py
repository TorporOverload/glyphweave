from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from app.core.service.launcher_service import open_with_default_app
from app.core.service.models import OpenFileResult, UnlockedFileInfo, VaultContext


def get_mounted_open_result(
    context: VaultContext,
    *,
    file_ref: Any,
    launch_in_default_app: bool,
) -> OpenFileResult | None:
    """Return an OpenFileResult for an already-mounted file, or None if not mounted."""
    mounts = context.mounts
    if not mounts or not mounts.is_mounted(file_ref.id):
        return None

    mounted_obj = mounts.get_mounted_path(file_ref.id)
    mounted_path: Path | None = (
        cast(Path, mounted_obj) if isinstance(mounted_obj, Path) else None
    )
    if launch_in_default_app and mounted_path and mounted_path.exists():
        open_with_default_app(mounted_path)

    return OpenFileResult(
        opened=True,
        source="mount",
        file_ref_id=file_ref.id,
        file_name=file_ref.name,
        file_path=mounted_path,
        message="File is already mounted",
    )


def mount_file(
    context: VaultContext,
    *,
    file_ref: Any,
    launch_in_default_app: bool,
) -> OpenFileResult | None:
    """Mount a vault file via FUSE and return the open result, or None if FUSE is
    unavailable."""
    mounts = context.mounts
    if not mounts:
        return None

    info = mounts.mount_and_open(file_ref.id, open_in_app=launch_in_default_app)
    if not info:
        return None

    return OpenFileResult(
        opened=True,
        source="mount",
        file_ref_id=info.file_ref_id,
        file_name=file_ref.name,
        file_path=info.file_path,
        message="Mounted and opened file",
    )


def list_mounted_unlocked_files(context: VaultContext) -> list[UnlockedFileInfo]:
    """Return info for all files currently open via FUSE mounts."""
    mounts = context.mounts
    if not mounts:
        return []

    return [
        UnlockedFileInfo(
            source="mount",
            file_ref_id=info.file_ref_id,
            file_name=info.file_name,
            file_path=info.file_path,
            opened_at=info.mounted_at,
        )
        for info in mounts.get_active_mounts().values()
    ]


def reopen_mounted_file(context: VaultContext, file_ref_id: int) -> str | None:
    """Re-launch the default app for an already mounted file, or return None if not
    mounted."""
    mounts = context.mounts
    if not mounts or not mounts.is_mounted(file_ref_id):
        return None

    mounted_obj = mounts.get_mounted_path(file_ref_id)
    mounted_path: Path | None = (
        cast(Path, mounted_obj) if isinstance(mounted_obj, Path) else None
    )
    if not mounted_path or not mounted_path.exists():
        raise FileNotFoundError("Mounted file path is not available")

    open_with_default_app(mounted_path)
    return "Opened mounted file"


def unmount_mounted_file(context: VaultContext, file_ref_id: int) -> str | None:
    """Unmount a FUSE-mounted file in the background, or return None if not mounted."""
    mounts = context.mounts
    if not mounts or not mounts.is_mounted(file_ref_id):
        return None

    if mounts.unmount(file_ref_id, background=True):
        return "Unmount started in background"
    return "File is no longer mounted"
