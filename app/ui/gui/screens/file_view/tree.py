"""file-tree handler helpers for File view."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QMenu,
    QTreeWidgetItem,
    QTreeWidgetItemIterator,
)

from app.ui.gui.setup import TOKENS
from app.ui.gui.setup.icons import tinted_icon

from .models import _TREE_PATH_ROLE

if TYPE_CHECKING:
    from .screen import FileViewScreen


def populate_tree(screen: "FileViewScreen") -> None:
    """Build the sidebar tree.

    The vault name is the single top-level row (path ``"/"``); folder
    entries hang underneath it. The QTreeWidget's built-in branch
    decoration shows the chevron, so the root reads as expandable."""
    screen.tree.clear()

    _vault_icon = tinted_icon("vault", size=14, color=TOKENS.colors.text_secondary)
    _folder_icon = tinted_icon("folder", size=14, color=TOKENS.colors.text_muted)

    # Vault root row.
    root = QTreeWidgetItem([screen._vault_name or "Vault"])
    root.setData(0, _TREE_PATH_ROLE, "/")
    root.setIcon(0, _vault_icon)
    root_font = root.font(0)
    root_font.setBold(True)
    root.setFont(0, root_font)
    screen.tree.addTopLevelItem(root)

    folder_entries = [e for e in screen._file_entries if e.is_folder]
    path_to_item: dict[str, QTreeWidgetItem] = {}

    for entry in folder_entries:
        item = QTreeWidgetItem([entry.name])
        item.setData(0, _TREE_PATH_ROLE, entry.path)
        item.setIcon(0, _folder_icon)
        path_to_item[entry.path] = item

    for entry in folder_entries:
        parent_path = entry.parent_path.rstrip("/") or "/"
        item = path_to_item[entry.path]
        if parent_path == "/":
            root.addChild(item)
        else:
            parent_item = path_to_item.get(parent_path)
            if parent_item is not None:
                parent_item.addChild(item)
            else:
                # Orphaned folder (parent missing) - attach to root rather
                # than silently drop.
                root.addChild(item)

    screen.tree.expandAll()


def handle_tree_selection_changed(screen: "FileViewScreen") -> None:
    item = screen.tree.currentItem()
    if item is None:
        return
    path = item.data(0, _TREE_PATH_ROLE)
    if not isinstance(path, str):
        return
    if path == "/":
        # Root row exists to act as a vault picker, not a navigation target;
        # VaultTreePanel handles the click and fires vault_switch_requested.
        return
    screen._current_folder_path = path
    screen._render_breadcrumbs()
    screen._refresh_table_for_current_folder()


def activate_tree_item(
    screen: "FileViewScreen",
    item: QTreeWidgetItem,
    _column: int = 0,
) -> None:
    """Adapter for ``QTreeWidget.itemDoubleClicked`` - pulls the virtual
    path off the item and forwards to ``activate_tree_path``."""
    if item is None:
        return
    path = item.data(0, _TREE_PATH_ROLE)
    if isinstance(path, str):
        activate_tree_path(screen, path)


def activate_tree_path(screen: "FileViewScreen", path: str) -> None:
    if path == "/":
        # Root row is non-navigational (acts as a vault picker).
        return
    screen._current_folder_path = path
    select_tree_path(screen, path)
    screen._render_breadcrumbs()
    screen._refresh_table_for_current_folder()


def select_tree_path(screen: "FileViewScreen", path: str) -> None:
    item = find_tree_item_by_path(screen, path)
    if item is not None:
        screen.tree.setCurrentItem(item)


def find_tree_item_by_path(
    screen: "FileViewScreen", path: str
) -> QTreeWidgetItem | None:
    iterator = QTreeWidgetItemIterator(screen.tree)
    while iterator.value():
        item = iterator.value()
        if item.data(0, _TREE_PATH_ROLE) == path:
            return item
        iterator += 1
    return None


def on_tree_item_expanded(screen: "FileViewScreen", index) -> None:
    """Swap folder icon to open-folder when an item is expanded."""
    item = screen.tree.itemFromIndex(index)
    if item is None:
        return
    if item.data(0, _TREE_PATH_ROLE) == "/":
        return  # vault root keeps its vault icon
    item.setIcon(0, tinted_icon("folder-open", size=14, color=TOKENS.colors.text_muted))


def on_tree_item_collapsed(screen: "FileViewScreen", index) -> None:
    """Swap folder icon back to closed-folder when an item is collapsed."""
    item = screen.tree.itemFromIndex(index)
    if item is None:
        return
    if item.data(0, _TREE_PATH_ROLE) == "/":
        return  # vault root keeps its vault icon
    item.setIcon(0, tinted_icon("folder", size=14, color=TOKENS.colors.text_muted))


def show_tree_context_menu(screen: "FileViewScreen", pos) -> None:
    item = screen.tree.itemAt(pos)
    if item is None:
        return
    path = item.data(0, _TREE_PATH_ROLE)
    if not isinstance(path, str):
        return
    entry = screen._selected_entry()
    is_single_non_pending = entry is not None and not (
        entry.file_ref_id is not None
        and entry.file_ref_id in screen._pending_actions
    )

    menu = QMenu(screen)

    open_folder_action = menu.addAction("Open folder")
    open_folder_action.triggered.connect(
        lambda: activate_tree_path(screen, path)
    )

    menu.addSeparator()

    rename_action = menu.addAction("Rename")
    rename_action.setEnabled(is_single_non_pending)
    rename_action.triggered.connect(screen._prompt_rename)

    move_action = menu.addAction("Move")
    move_action.setEnabled(is_single_non_pending)
    move_action.triggered.connect(screen._prompt_move)

    menu.addSeparator()

    export_action = menu.addAction("Export")
    export_action.triggered.connect(
        lambda: screen.export_requested.emit([path])
    )

    delete_action = menu.addAction("Delete")
    delete_action.triggered.connect(
        lambda: screen.delete_requested.emit([path])
    )

    menu.addSeparator()

    copy_path_action = menu.addAction("Copy virtual path")
    copy_path_action.triggered.connect(
        lambda: screen._copy_virtual_path(path if path is not None else None)
    )

    menu.exec(screen.tree.viewport().mapToGlobal(pos))
