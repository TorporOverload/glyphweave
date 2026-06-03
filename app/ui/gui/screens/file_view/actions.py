"""Action helpers - rename / move / cut / copy / paste / virtual-path
clipboard / per-file pending state."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QApplication, QDialog, QWidget

from .dialogs import CreateFolderDialog, MoveDialog, RenameDialog

if TYPE_CHECKING:
    from .screen import FileViewScreen


def update_rename_button_state(
    screen: "FileViewScreen", paths: list[str]
) -> None:
    """Enable rename button only when exactly one non-pending item is selected."""
    if len(paths) != 1:
        screen.rename_button.setEnabled(False)
        return
    entry = next(
        (e for e in screen._file_entries if e.path == paths[0]), None
    )
    if entry is None:
        screen.rename_button.setEnabled(False)
        return
    is_pending = (
        entry.file_ref_id is not None
        and entry.file_ref_id in screen._pending_actions
    )
    screen.rename_button.setEnabled(not is_pending)


def update_move_button_state(
    screen: "FileViewScreen", paths: list[str]
) -> None:
    if not paths:
        screen.move_button.setEnabled(False)
        return
    for path in paths:
        entry = next(
            (e for e in screen._file_entries if e.path == path), None
        )
        if entry is None or (
            entry.file_ref_id is not None
            and entry.file_ref_id in screen._pending_actions
        ):
            screen.move_button.setEnabled(False)
            return
    screen.move_button.setEnabled(True)


def prompt_create_folder(screen: "FileViewScreen") -> None:
    dialog = CreateFolderDialog(
        screen.window() if isinstance(screen.window(), QWidget) else screen
    )
    if dialog.exec() != int(QDialog.DialogCode.Accepted):
        return
    folder_name = dialog.folder_name()
    if folder_name:
        screen.create_folder_requested.emit(
            folder_name, screen._current_folder_path
        )


def prompt_rename(screen: "FileViewScreen") -> None:
    entry = screen._selected_entry()
    if entry is None:
        return
    dialog = RenameDialog(entry.name, parent=screen)
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return
    new_name = dialog.new_name()
    if not new_name or new_name == entry.name:
        return
    screen.rename_requested.emit(entry.path, new_name)


def prompt_move(screen: "FileViewScreen") -> None:
    paths = screen._selected_table_paths()
    if not paths:
        return
    hint = paths[0] if len(paths) == 1 else f"{len(paths)} items"
    dialog = MoveDialog(
        hint,
        screen._file_entries,
        screen._vault_name,
        parent=screen,
    )
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return
    dest = dialog.destination_path
    if not dest:
        return
    screen.move_requested.emit((paths, dest))


def on_cut(screen: "FileViewScreen", paths: list[str]) -> None:
    screen._clipboard = {"mode": "cut", "paths": list(paths)}
    screen.paste_button.setEnabled(True)
    screen.cut_requested.emit(list(paths))


def on_copy(screen: "FileViewScreen", paths: list[str]) -> None:
    screen._clipboard = {"mode": "copy", "paths": list(paths)}
    screen.paste_button.setEnabled(True)
    screen.copy_requested.emit(list(paths))


def on_paste(screen: "FileViewScreen") -> None:
    if screen._clipboard is None:
        return
    # The destination is the current folder. Backend handler decides what
    # cut vs copy means (move vs duplicate).
    screen.paste_requested.emit(screen._current_folder_path or "/")
    # Cut clears the clipboard after a single paste; copy persists.
    if screen._clipboard.get("mode") == "cut":
        screen._clipboard = None
        screen.paste_button.setEnabled(False)


def copy_virtual_path(
    screen: "FileViewScreen", path: str | None
) -> None:
    if path is None:
        return
    full_path = f"/{screen._vault_name}{path}"
    clipboard = QApplication.clipboard()
    clipboard.setText(full_path)


def emit_current_folder_changed(screen: "FileViewScreen") -> None:
    """Emit ``current_folder_changed`` so AppShell breadcrumbs can update.

    ``parts`` always begins with the vault name (parts[0]) followed by the
    in-vault folder segments, e.g. ``["Research Vault", "Documents",
    "Drafts"]``."""
    parts: list[str] = [screen._vault_name or "glyphweave"]
    if screen._current_folder_path and screen._current_folder_path != "/":
        parts.extend(
            segment
            for segment in screen._current_folder_path.strip("/").split("/")
            if segment
        )
    screen.current_folder_changed.emit(parts)


def set_file_pending(
    screen: "FileViewScreen",
    file_ref_id: int,
    pending: bool,
    label: str = "",
) -> None:
    if pending:
        screen._pending_actions[file_ref_id] = label
    elif file_ref_id in screen._pending_actions:
        del screen._pending_actions[file_ref_id]
    screen._refresh_table_for_current_folder()
