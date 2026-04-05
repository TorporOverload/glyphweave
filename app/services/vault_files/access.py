from __future__ import annotations

from app.infrastructure.persistence.db_dump_service import flush_db_dump_hook
from app.infrastructure.platform.launcher import open_with_default_app
from app.services.models import UnlockedFileInfo

from .vault_file_fallback import finalize_fallback_open
from .vault_file_mounts import reopen_mounted_file, unmount_mounted_file
from .vault_file_opening import open_file_by_ref as open_file_from_vault
from .vault_file_sessions import cleanup_unlocked_files, list_unlocked_files


def open_file_by_ref(service, file_ref_id: int, launch_in_default_app: bool = True):
    return open_file_from_vault(
        service.context,
        fallback_opens=service.fallback_opens,
        file_service=service._require_file_service(),
        encryption_service=service._require_encryption_service(),
        file_ref_id=file_ref_id,
        launch_in_default_app=launch_in_default_app,
    )


def list_unlocked(service) -> list[UnlockedFileInfo]:
    return list_unlocked_files(service.context, service.fallback_opens)


def reopen_unlocked(service, file_ref_id: int) -> str:
    mounted = reopen_mounted_file(service.context, file_ref_id)
    if mounted is not None:
        return mounted

    pending = service.fallback_opens.get(file_ref_id)
    if pending and pending.temp_path.exists():
        open_with_default_app(pending.temp_path)
        return "Opened cached decrypted file"

    raise FileNotFoundError("File is not currently unlocked")


def unmount_unlocked(service, file_ref_id: int) -> str:
    mounted = unmount_mounted_file(service.context, file_ref_id)
    if mounted is not None:
        return mounted

    return finalize_fallback_open(
        service.context,
        fallback_opens=service.fallback_opens,
        file_service=service._require_file_service(),
        folder_service=service._require_folder_service(),
        encryption_service=service._require_encryption_service(),
        event_emitter=service._build_event_emitter(),
        file_ref_id=file_ref_id,
    )


def cleanup(service, *, flush_db_dump: bool = True) -> None:
    runtime = service.context.event_replay_runtime
    if runtime is not None:
        runtime.stop()
        service.context.event_replay_runtime = None
    cleanup_unlocked_files(
        service.context,
        fallback_opens=service.fallback_opens,
        file_service=service._require_file_service(),
        folder_service=service._require_folder_service(),
        encryption_service=service._require_encryption_service(),
    )
    session_factory = service.context.session_factory
    if flush_db_dump and session_factory is not None:
        flush_db_dump_hook(session_factory)
