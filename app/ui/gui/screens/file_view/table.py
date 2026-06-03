"""File-table refresh / selection / context-menu helpers for
:class:`FileViewScreen`."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush
from PySide6.QtWidgets import (
    QFileDialog,
    QMenu,
    QMessageBox,
    QTableWidgetItem,
)

from app.ui.gui.setup import TOKENS

from .delegates import (
    FileNameDelegate,
    ROW_PAYLOAD_ROLE,
    TypeBadgeDelegate,
)

if TYPE_CHECKING:
    from .screen import FileViewScreen


def install_table_delegates(screen: "FileViewScreen") -> None:
    """Wire the painted delegates onto the file table.

    Called once from screen setup after ``screen.table`` exists. The
    delegates carry no per-row state - all data flows through the
    ``ROW_PAYLOAD_ROLE`` dict on each column-0 item.
    """
    if not getattr(screen, "_file_table_delegates_installed", False):
        screen._name_delegate = FileNameDelegate(screen.table)
        screen._badge_delegate = TypeBadgeDelegate(screen.table)
        screen.table.setItemDelegateForColumn(0, screen._name_delegate)
        screen.table.setItemDelegateForColumn(1, screen._badge_delegate)
        screen._file_table_delegates_installed = True


def refresh_for_current_folder(screen: "FileViewScreen") -> None:
    """Repopulate the file table for the currently navigated folder.

    Performance notes:
      * Row visuals are painted by ``FileNameDelegate`` /
        ``TypeBadgeDelegate``; the previous ``setCellWidget`` approach
        allocated 3-4 ``QWidget`` instances per row and was visibly slow
        past ~50 files.
      * ``setUpdatesEnabled(False)`` + ``setSortingEnabled(False)`` around
        the loop suppress per-row repaint and re-sort work.
      * ``setRowCount(N)`` allocates row storage once instead of growing
        the table N times via ``insertRow``.
    """
    install_table_delegates(screen)
    c = TOKENS.colors

    filtered = screen._file_entries
    if screen._current_folder_path != "/":
        filtered = [
            e
            for e in filtered
            if e.parent_path == screen._current_folder_path
        ]
    else:
        filtered = [e for e in filtered if e.parent_path == "/"]
    filtered = sorted(filtered, key=lambda e: (not e.is_folder, e.name.lower()))
    screen.table.set_empty(not filtered)

    unlocked_ids = {u.file_ref_id for u in screen._unlocked_entries}
    mono_caption_font = TOKENS.typography.caption.qfont(family="IBM Plex Mono")
    text_muted_brush = QBrush(c.text_muted)

    table = screen.table
    table.setUpdatesEnabled(False)
    sorting_was_enabled = table.isSortingEnabled()
    table.setSortingEnabled(False)
    try:
        table.clearContents()
        table.setRowCount(len(filtered))

        first_file_row: int | None = None
        for row, entry in enumerate(filtered):
            is_unlocked = (
                entry.file_ref_id is not None
                and entry.file_ref_id in unlocked_ids
                and not entry.is_folder
            )
            if entry.is_folder:
                row_icon, row_icon_color = "folder", c.text_secondary
            elif is_unlocked:
                row_icon, row_icon_color = (
                    "lock-simple-open",
                    c.status_warning_text,
                )
            else:
                row_icon, row_icon_color = entry.icon_name, c.text_secondary

            payload = {
                "icon_name": row_icon,
                "icon_color": row_icon_color,
                "name": entry.name,
                "type_label": "" if entry.is_folder else entry.type_label,
                "type_accent": entry.accent,
            }

            # Col 0 - virtual path (UserRole, used by selection lookups)
            # plus the delegate payload (ROW_PAYLOAD_ROLE).
            path_item = QTableWidgetItem()
            path_item.setData(Qt.ItemDataRole.UserRole, entry.path)
            path_item.setData(ROW_PAYLOAD_ROLE, payload)
            table.setItem(row, 0, path_item)

            # Col 1 - empty backing item; TypeBadgeDelegate paints from
            # the col-0 payload via index.sibling lookups would be slower,
            # so we duplicate the payload here for direct access.
            badge_item = QTableWidgetItem()
            badge_item.setData(ROW_PAYLOAD_ROLE, payload)
            table.setItem(row, 1, badge_item)

            # Col 2 - modified date, mono caption, muted.
            modified_item = QTableWidgetItem(entry.modified)
            modified_item.setTextAlignment(
                Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter
            )
            modified_item.setForeground(text_muted_brush)
            modified_item.setData(Qt.ItemDataRole.FontRole, mono_caption_font)
            table.setItem(row, 2, modified_item)

            if first_file_row is None and not entry.is_folder:
                first_file_row = row
    finally:
        if sorting_was_enabled:
            table.setSortingEnabled(True)
        table.setUpdatesEnabled(True)

    if hasattr(screen, "items_count_label"):
        screen.items_count_label.setText(f"{len(filtered)} items")

    # Auto-select the first non-folder row so the Properties pane has
    # content on initial load - matches the design which never shows an
    # empty inspector. ``clearContents`` above already dropped any prior
    # selection.
    if first_file_row is not None:
        table.selectRow(first_file_row)


def selected_table_paths(screen: "FileViewScreen") -> list[str]:
    paths: list[str] = []
    for item in screen.table.selectedItems():
        row = item.row()
        name_item = screen.table.item(row, 0)
        if name_item:
            path = name_item.data(Qt.ItemDataRole.UserRole)
            if isinstance(path, str) and path not in paths:
                paths.append(path)
    return paths


def sync_selected_file_from_table(screen: "FileViewScreen") -> None:
    paths = selected_table_paths(screen)
    screen.delete_button.setEnabled(bool(paths))
    screen.export_button.setEnabled(bool(paths))
    screen.copy_button.setEnabled(bool(paths))
    screen._update_rename_button_state(paths)
    screen._update_move_button_state(paths)
    if not paths:
        screen._clear_properties()
        return
    if len(paths) > 1:
        screen._show_multi_selection(paths)
        return
    screen._update_selection(paths[0])


def activate_selected_table_item(
    screen: "FileViewScreen", item: QTableWidgetItem
) -> None:
    path = item.data(Qt.ItemDataRole.UserRole)
    if not isinstance(path, str):
        return
    entry = next(
        (e for e in screen._file_entries if e.path == path), None
    )
    if entry is None:
        return
    if (
        entry.file_ref_id is not None
        and entry.file_ref_id in screen._pending_actions
    ):
        return
    if entry.is_folder:
        screen._current_folder_path = entry.path
        screen._select_tree_path(entry.path)
        screen._render_breadcrumbs()
        screen._refresh_table_for_current_folder()
        return
    if entry.file_ref_id is not None:
        screen.file_open_requested.emit(entry.file_ref_id)


def show_table_context_menu(screen: "FileViewScreen", pos) -> None:
    paths = selected_table_paths(screen)
    if not paths:
        return
    entry = screen._selected_entry() if len(paths) == 1 else None
    is_single_non_pending = entry is not None and not (
        entry.file_ref_id is not None
        and entry.file_ref_id in screen._pending_actions
    )
    is_file = entry is not None and not entry.is_folder

    # Move is allowed for any non-empty selection as long as no item is pending.
    is_moveable = bool(paths) and not any(
        (e := next((x for x in screen._file_entries if x.path == p), None))
        is not None
        and e.file_ref_id is not None
        and e.file_ref_id in screen._pending_actions
        for p in paths
    )

    menu = QMenu(screen)

    if is_file:
        open_action = menu.addAction("Open")
        open_action.setShortcut("Enter")
        open_action.triggered.connect(
            lambda: (
                screen.file_open_requested.emit(entry.file_ref_id)
                if entry.file_ref_id is not None
                else None
            )
        )
        is_unlocked = any(
            u.file_ref_id == entry.file_ref_id
            for u in screen._unlocked_entries
        )
        lock_label = "Lock file" if is_unlocked else "Unlock file"
        lock_action = menu.addAction(lock_label)
        if is_unlocked:
            lock_action.triggered.connect(
                lambda: screen.unlocked_lock_requested.emit(
                    entry.file_ref_id
                )
            )
        else:
            lock_action.triggered.connect(
                lambda: screen.file_open_requested.emit(entry.file_ref_id)
            )
        menu.addSeparator()

    cut_action = menu.addAction("Cut")
    cut_action.setShortcut("Ctrl+X")
    cut_action.triggered.connect(lambda: screen._on_cut(paths))

    copy_action = menu.addAction("Copy")
    copy_action.setShortcut("Ctrl+C")
    copy_action.triggered.connect(lambda: screen._on_copy(paths))

    paste_action = menu.addAction("Paste")
    paste_action.setShortcut("Ctrl+V")
    paste_action.setEnabled(screen._clipboard is not None)
    paste_action.triggered.connect(screen._on_paste)

    rename_action = menu.addAction("Rename")
    rename_action.setShortcut("F2")
    rename_action.setEnabled(is_single_non_pending)
    rename_action.triggered.connect(screen._prompt_rename)

    move_action = menu.addAction("Move…")
    move_action.setEnabled(is_moveable)
    move_action.triggered.connect(screen._prompt_move)

    menu.addSeparator()

    export_action = menu.addAction("Export…")
    export_action.triggered.connect(
        lambda: screen.export_requested.emit(paths)
    )

    menu.addSeparator()

    delete_action = menu.addAction("Delete")
    delete_action.setShortcut("Del")
    delete_action.triggered.connect(screen._request_delete)

    menu.addSeparator()

    copy_path_action = menu.addAction("Copy virtual path")
    copy_path_action.triggered.connect(
        lambda: screen._copy_virtual_path(
            paths[0] if len(paths) == 1 else None
        )
    )

    menu.exec(screen.table.viewport().mapToGlobal(pos))


def request_import(screen: "FileViewScreen") -> None:
    paths, _ = QFileDialog.getOpenFileNames(
        screen,
        "Import Files to Vault",
        str(Path.home()),
    )
    if paths:
        screen.import_requested.emit(paths, screen._current_folder_path)


def handle_dropped_paths(
    screen: "FileViewScreen", paths: list[str]
) -> None:
    if paths:
        screen.import_requested.emit(paths, screen._current_folder_path)


def request_delete(screen: "FileViewScreen") -> None:
    selected_paths = selected_table_paths(screen)
    if not selected_paths:
        return
    item_label = "item" if len(selected_paths) == 1 else "items"
    choice = QMessageBox.question(
        screen,
        "Delete from vault",
        f"Delete {len(selected_paths)} {item_label} from the vault?",
    )
    if choice != QMessageBox.StandardButton.Yes:
        return
    screen.delete_requested.emit(selected_paths)
