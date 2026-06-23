"""Background task functions executed on a :class:`TaskThread`.
Each takes the window and returns a payload the UI thread can use directly."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..gui_utils import (
    CreatedVaultResult,
    FileViewPayload,
    PreparedVaultResult,
)
from ..screens import VaultListEntry
from . import metadata as _meta

if TYPE_CHECKING:
    from ..glyphweave_ui import GlypheaveGUI


def load_vault_entries(window: "GlypheaveGUI") -> list[VaultListEntry]:
    return _meta.load_vault_entries(window)


def delete_vault_record_and_reload(
    window: "GlypheaveGUI", vault_id: str
) -> list[VaultListEntry]:
    window.service.delete_local_vault_record(vault_id)
    return _meta.load_vault_entries(window)


def create_vault(
    window: "GlypheaveGUI",
    vault_path: Path,
    vault_name: str,
    password: str,
) -> CreatedVaultResult:
    recovery_phrase = window.service.create_new_vault(vault_path, vault_name, password)
    return CreatedVaultResult(
        vault_id=str(window.service.context.vault_id or ""),
        recovery_words=recovery_phrase.split(),
    )


def prepare_vault(window: "GlypheaveGUI", entry: VaultListEntry) -> PreparedVaultResult:
    window.service.prepare_existing_vault(
        Path(entry.path),
        fallback_alias=entry.name,
        fallback_vault_id=entry.vault_id,
    )
    return PreparedVaultResult(
        vault_id=entry.vault_id, name=entry.name, path=entry.path
    )


def import_and_prepare(window: "GlypheaveGUI", vault_path: Path) -> PreparedVaultResult:
    """Import a vault and prepare its context for use."""
    imported = window.service.import_vault(vault_path)
    imported_id = str(imported["vault_id"])
    imported_name = str(imported.get("vault_alias") or vault_path.name)
    imported_path = str(imported.get("path") or vault_path)
    # Note: import_vault already calls prepare_existing_vault internally,
    # so we don't need to call it again here
    return PreparedVaultResult(
        vault_id=imported_id,
        name=imported_name,
        path=imported_path,
    )


def unlock_and_load(window: "GlypheaveGUI", passphrase: str) -> FileViewPayload:
    window.service.open_existing_vault(passphrase)
    return _meta.build_file_view_payload(window)


def load_file_view_payload(window: "GlypheaveGUI") -> FileViewPayload:
    return _meta.build_file_view_payload(window)


def open_and_refresh(window: "GlypheaveGUI", file_ref_id: int) -> FileViewPayload:
    window.service.open_file_by_ref(file_ref_id)
    return _meta.build_file_view_payload(window)


def reopen_and_refresh(window: "GlypheaveGUI", file_ref_id: int) -> FileViewPayload:
    window.service.reopen_unlocked(file_ref_id)
    return _meta.build_file_view_payload(window)


def lock_and_refresh(window: "GlypheaveGUI", file_ref_id: int) -> FileViewPayload:
    window.service.unmount_unlocked(file_ref_id)
    return _meta.build_file_view_payload(window)


# Emit a partial refresh every N files so the table stays alive during
# long batch imports. 50 keeps refresh cost low (one full payload build
# per batch, which means a DB read of all references) while still feeling
# responsive - at typical import rates the user sees rows appear in
# perceptible chunks rather than all-or-nothing.
_IMPORT_REFRESH_EVERY = 50


def import_and_refresh(
    window: "GlypheaveGUI",
    import_paths: list[str],
    destination_folder_virtual_path: str,
) -> FileViewPayload:
    expand_jobs = _meta.expand_import_jobs(
        import_paths, destination_folder_virtual_path
    )
    total = len(expand_jobs)
    for index, (source_path, target_parent) in enumerate(expand_jobs):
        window._task_progress.emit(index + 1, total, source_path.name)
        window.service.add_file(source_path, dest_parent_virtual_path=target_parent)
        completed = index + 1
        if completed % _IMPORT_REFRESH_EVERY == 0 and completed != total:
            window._task_intermediate_refresh.emit(
                _meta.build_file_view_payload(window)
            )
    window._task_progress.emit(total, total, "")
    return _meta.build_file_view_payload(window)


def sync_and_refresh(
    window: "GlypheaveGUI",
) -> tuple:
    """Replay pending sync events with per-event progress, then rebuild
    the file-view payload so the UI can refresh in one shot."""

    def _progress(current: int, total: int, label: str) -> None:
        window._sync_progress.emit(current, total, label)

    result = window.service.replay_pending_events(progress_callback=_progress)
    payload = _meta.build_file_view_payload(window)
    return (result, payload)


def delete_and_refresh(
    window: "GlypheaveGUI",
    source_virtual_paths: list[str],
) -> FileViewPayload:
    window.service.delete_entries(source_virtual_paths)
    return _meta.build_file_view_payload(window)


def create_folder_and_refresh(
    window: "GlypheaveGUI",
    folder_name: str,
    parent_virtual_path: str,
) -> FileViewPayload:
    window.service.create_folder(folder_name, parent_virtual_path)
    return _meta.build_file_view_payload(window)


def export_entries(
    window: "GlypheaveGUI",
    source_virtual_paths: list[str],
    destination_dir: Path,
) -> list[Path]:
    return list(window.service.export_entries(source_virtual_paths, destination_dir))
