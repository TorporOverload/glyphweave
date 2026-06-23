"""File-operation actions invoked by the file-view (open / lock / import /
delete / rename / move / export). Each is a thin wrapper that schedules the
matching ``_window_tasks.*`` function on a background thread."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QFileDialog, QMessageBox

from . import tasks as _tasks

if TYPE_CHECKING:
    from ..glyphweave_ui import GlypheaveGUI


def _resolve_file_name(window: "GlypheaveGUI", file_ref_id: int) -> str:
    """Look up a display name for the given file_ref_id from either the
    main file list or the unlocked-file list. Returns ``""`` if not found."""
    if not hasattr(window, "file_view"):
        return ""
    fv = window.file_view
    entry = fv.find_entry_by_ref_id(file_ref_id)
    if entry is not None and entry.name:
        return entry.name
    unlocked = fv.find_unlocked_by_ref_id(file_ref_id)
    return unlocked.name if unlocked else ""


def open_file_from_view(window: "GlypheaveGUI", file_ref_id: int) -> None:
    name = _resolve_file_name(window, file_ref_id)

    def _before() -> None:
        window.add_toast("info", f"Opening {name or 'file'}…")
        window.file_view.set_file_pending(file_ref_id, True, "Opening")

    window._run_task(
        lambda: _tasks.open_and_refresh(window, file_ref_id),
        on_success=lambda payload: window._handle_file_view_loaded(
            payload, show_screen=False
        ),
        error_title="Open failed",
        before=_before,
        after=lambda: window.file_view.set_file_pending(file_ref_id, False),
        block_ui=False,
    )


def reopen_unlocked_file(window: "GlypheaveGUI", file_ref_id: int) -> None:
    name = _resolve_file_name(window, file_ref_id)

    def _before() -> None:
        window.add_toast("info", f"Opening {name or 'file'}…")
        window.file_view.set_file_pending(file_ref_id, True, "Opening")

    window._run_task(
        lambda: _tasks.reopen_and_refresh(window, file_ref_id),
        on_success=lambda payload: window._handle_file_view_loaded(
            payload, show_screen=False
        ),
        error_title="Open failed",
        before=_before,
        after=lambda: window.file_view.set_file_pending(file_ref_id, False),
        block_ui=False,
    )


def lock_unlocked_file(window: "GlypheaveGUI", file_ref_id: int) -> None:
    # Surface the file name in the toast when available.
    name = ""
    if hasattr(window, "file_view"):
        entry = window.file_view.find_unlocked_by_ref_id(file_ref_id)
        if entry:
            name = entry.name
    window.add_toast("info", f"Locking {name or 'file'}…")

    def _on_error(msg: str) -> None:
        window.file_view.set_file_pending(file_ref_id, False)
        window.add_toast("error", f"Lock failed: {msg}")
        # Still refresh - mount state may have partially changed.
        window.refresh_file_view()

    window._run_task(
        lambda: _tasks.lock_and_refresh(window, file_ref_id),
        on_success=lambda payload: window._handle_file_view_loaded(
            payload, show_screen=False
        ),
        on_error=_on_error,
        error_title="Lock failed",
        before=lambda: window.file_view.set_file_pending(file_ref_id, True, "Locking"),
        after=lambda: window.file_view.set_file_pending(file_ref_id, False),
        block_ui=False,
    )

    # Safety-net poll: rebuild the unlocked panel from the service in case
    # the task's on_success path doesn't update the UI correctly. Guard
    # against firing during shutdown so we don't poke a torn-down window.
    def _safe_refresh() -> None:
        if not getattr(window, "_shutdown_started", False):
            window.refresh_file_view()

    QTimer.singleShot(3000, _safe_refresh)


def import_into_vault(
    window: "GlypheaveGUI",
    paths: object,
    destination_folder_virtual_path: str,
) -> None:
    import_paths = [str(path) for path in paths] if isinstance(paths, list) else []
    if not import_paths:
        selected_files, _ = QFileDialog.getOpenFileNames(
            window,
            "Import Files to Vault",
            str(Path.home()),
        )
        import_paths = selected_files
    if not import_paths:
        return

    def _on_error(msg: str) -> None:
        window.app_shell.hide_importing_status()
        window.add_toast("error", f"Import failed: {msg}")

    window._run_task(
        lambda: _tasks.import_and_refresh(
            window, import_paths, destination_folder_virtual_path
        ),
        on_success=lambda payload: window._handle_file_view_loaded(
            payload, show_screen=False
        ),
        on_error=_on_error,
        before=lambda: window.app_shell.show_importing_status("Importing…"),
        after=window.app_shell.hide_importing_status,
        block_ui=False,
    )


def delete_selected_entries(window: "GlypheaveGUI", paths: object) -> None:
    selected_paths = [str(path) for path in paths] if isinstance(paths, list) else []
    if not selected_paths:
        return
    item_label = "item" if len(selected_paths) == 1 else "items"
    choice = QMessageBox.question(
        window,
        "Delete from vault",
        f"Delete {len(selected_paths)} {item_label} from the vault?",
    )
    if choice != QMessageBox.StandardButton.Yes:
        return

    window._run_task(
        lambda: _tasks.delete_and_refresh(window, selected_paths),
        on_success=lambda payload: window._handle_file_view_loaded(
            payload, show_screen=False
        ),
        error_title="Delete failed",
    )


def create_folder_in_vault(
    window: "GlypheaveGUI",
    folder_name: str,
    parent_virtual_path: str,
) -> None:
    if not folder_name.strip():
        window._show_warning(
            "Folder name required",
            "Enter a folder name before creating it.",
        )
        return
    window._run_task(
        lambda: _tasks.create_folder_and_refresh(
            window, folder_name, parent_virtual_path
        ),
        on_success=lambda payload: window._handle_file_view_loaded(
            payload, show_screen=False
        ),
        error_title="Create folder failed",
        block_ui=False,
    )


def export_selected_entries(window: "GlypheaveGUI", paths: object) -> None:
    selected_paths = [str(path) for path in paths] if isinstance(paths, list) else []
    if not selected_paths:
        return
    destination = QFileDialog.getExistingDirectory(
        window, "Export From Vault", str(Path.home())
    )
    if not destination:
        return

    def _on_success(exported: object) -> None:
        files = exported if isinstance(exported, list) else []
        if len(files) == 1:
            window.add_toast(
                "success", f"Exported {Path(files[0]).name} to {destination}"
            )
        elif len(files) > 1:
            window.add_toast("success", f"Exported {len(files)} files to {destination}")
        else:
            window.add_toast("success", f"Exported to {destination}")

    window._run_task(
        lambda: _tasks.export_entries(window, selected_paths, Path(destination)),
        on_success=_on_success,
        error_title="Export failed",
        block_ui=False,
    )


def rename_entry(window: "GlypheaveGUI", virtual_path: str, new_name: str) -> None:
    def task():
        window.service.rename_entry(virtual_path, new_name)

    window._run_task(
        task,
        on_success=lambda _: window.refresh_file_view(),
        error_title="Rename failed",
        block_ui=False,
    )


def move_entries(window: "GlypheaveGUI", payload: tuple[list[str], str]) -> None:
    source_virtual_paths, destination_folder_virtual_path = payload

    def task():
        window.service.move_entries(
            source_virtual_paths, destination_folder_virtual_path
        )

    window._run_task(
        task,
        on_success=lambda _: window.refresh_file_view(),
        error_title="Move failed",
        block_ui=False,
    )


def import_existing_vault(window: "GlypheaveGUI") -> None:
    selected = QFileDialog.getExistingDirectory(
        window, "Choose Existing Vault", str(Path.home())
    )
    if not selected:
        return
    window._run_task(
        lambda: _tasks.import_and_prepare(window, Path(selected)),
        on_success=window._handle_prepared_vault,
        error_title="Import failed",
        block_ui=False,
    )
