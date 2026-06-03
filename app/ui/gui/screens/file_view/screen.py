"""Main file-view screen - composition root for the inner content area
(action toolbar + file table + inspector). The chrome (TopBar / breadcrumbs
/ sidebar / footer) lives in :class:`AppShell`. This class wires the child
widgets together; the heavy lifting lives in the ``_build`` / ``_table`` /
``_tree`` / ``_inspector`` / ``_actions`` helper modules so this file stays
under the per-file line cap."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QTableWidgetItem,
    QTreeWidget,
    QWidget,
)

from app.ui.gui.setup import Role, set_properties

from . import actions, build, inspector, table, tree
from .models import FileEntry, UnlockedFile
from .widgets import UnlockedFileCard


class FileViewScreen(QWidget):
    file_open_requested = Signal(int)
    unlocked_open_requested = Signal(int)
    unlocked_lock_requested = Signal(int)
    import_requested = Signal(object, str)
    delete_requested = Signal(object)
    create_folder_requested = Signal(str, str)
    export_requested = Signal(object)
    rename_requested = Signal(str, str)
    move_requested = Signal(object)

    # Clipboard operations from the right-click context menu / toolbar.
    cut_requested = Signal(object)  # list[str] of virtual paths
    copy_requested = Signal(object)  # list[str] of virtual paths
    paste_requested = Signal(str)  # destination folder virtual path

    # Folder navigation - emitted when the active folder changes so the
    # AppShell breadcrumbs can re-render.
    current_folder_changed = Signal(list)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._vault_name = "glyphweave"
        self._current_folder_path = "/"
        self._file_entries: list[FileEntry] = []
        self._unlocked_entries: list[UnlockedFile] = []
        self._unlocked_cards: dict[str, UnlockedFileCard] = {}
        self._pending_actions: dict[int, str] = {}
        self._selected_path: str | None = None
        # Local clipboard model - tracks the last cut/copy operation so
        # Paste can be enabled/disabled without round-tripping to the backend.
        self._clipboard: dict | None = None
        self._build_ui()
        self._populate_tree()
        self._populate_unlocked_cards()
        self._refresh_table_for_current_folder()
        self._set_active_tab("properties")

    def _build_ui(self) -> None:
        """Build only the inner content (center file table + right inspector).

        AppShell already owns the surrounding - TopBar, breadcrumbs,
        sidebar (VaultTreePanel hosts ``self.tree`` directly) and StatusFooter.
        Building any of that here would double-paint inside the content area.
        """
        set_properties(self, role=Role.FILE_VIEW)

        # The QTreeWidget is created here but never added to a layout in
        # this screen - AppShell reparents it into VaultTreePanel via
        # ``tree_widget()``. Keeping it owned by the screen lets all the
        # existing tree/path handlers continue to work without changes.
        self.tree = QTreeWidget(self)
        self.tree.setHeaderHidden(True)
        self.tree.setRootIsDecorated(True)
        self.tree.setIndentation(16)
        self.tree.setUniformRowHeights(True)
        self.tree.setAnimated(False)
        self.tree.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.tree.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.tree.setProperty("showDropIndicator", False)
        # Show horizontal scroll when long folder names overflow; no eliding.
        self.tree.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.tree.setHorizontalScrollMode(
            QAbstractItemView.ScrollMode.ScrollPerPixel
        )
        self.tree.setTextElideMode(Qt.TextElideMode.ElideNone)
        header = self.tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(False)
        set_properties(self.tree, role=Role.FILE_TREE)
        self.tree.currentItemChanged.connect(
            self._handle_tree_selection_changed
        )
        # itemDoubleClicked emits (QTreeWidgetItem, column) - extract the
        # path string from the item before handing off to _activate_tree_path.
        self.tree.itemDoubleClicked.connect(self._activate_tree_item)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(
            self._show_tree_context_menu
        )
        # Swap folder icon to open/closed variant as items expand/collapse.
        self.tree.expanded.connect(self._on_tree_item_expanded)
        self.tree.collapsed.connect(self._on_tree_item_collapsed)

        build.build_ui(self)

        # Ctrl+A → select every row in the file table. Scoped to this widget;
        # Qt auto-disables it while FileViewScreen is hidden in the stack.
        select_all = QShortcut(QKeySequence.StandardKey.SelectAll, self)
        select_all.activated.connect(self.table.selectAll)

    def set_vault_data(
        self,
        *,
        vault_name: str,
        entries: list[FileEntry],
        unlocked_files: list[UnlockedFile],
        preserve_navigation: bool = False,
    ) -> None:
        self._vault_name = vault_name
        if not preserve_navigation:
            self._current_folder_path = "/"
        self._file_entries = list(entries)
        self._unlocked_entries = list(unlocked_files)
        try:
            self._populate_tree()
            if self._current_folder_path != "/":
                self._select_tree_path(self._current_folder_path)
            self._refresh_table_for_current_folder()
        finally:
            # Always refresh the unlocked panel and breadcrumbs even if the
            # tree/table rebuild above fails - these must reflect the new
            # unlocked_files list regardless of other UI state.
            self._populate_unlocked_cards()
            self._emit_current_folder_changed()

    def clear_vault_data(self) -> None:
        self._vault_name = "glyphweave"
        self._current_folder_path = "/"
        self._file_entries = []
        self._unlocked_entries = []
        self._selected_path = None

    def has_unlocked_files(self) -> bool:
        return len(self._unlocked_entries) > 0

    def get_entries_snapshot(self) -> list[FileEntry]:
        """Return a shallow copy of the current file entries. Used by
        sibling widgets that need to render the live folder structure
        (e.g. the conflict-resolution restore overlay) without reaching
        into private state."""
        return list(self._file_entries)

    def find_entry_by_ref_id(self, file_ref_id: int) -> FileEntry | None:
        for entry in self._file_entries:
            if entry.file_ref_id == file_ref_id:
                return entry
        return None

    def find_unlocked_by_ref_id(self, file_ref_id: int) -> UnlockedFile | None:
        for entry in self._unlocked_entries:
            if entry.file_ref_id == file_ref_id:
                return entry
        return None

    def get_clipboard(self) -> dict | None:
        """Return the current clipboard payload (cut/copy state) or None."""
        return self._clipboard

    def get_selected_paths(self) -> list[str]:
        return list(getattr(self, "_selected_paths", []) or [])

    def lock_all_unlocked(self) -> None:
        for entry in self._unlocked_entries:
            self.unlocked_lock_requested.emit(entry.file_ref_id)

    def tree_widget(self) -> QTreeWidget:
        """Return the tree widget for use by VaultTreePanel."""
        return self.tree

    def navigate_to_folder(self, path: str) -> None:
        """Navigate to the specified folder path in the file view."""
        self._current_folder_path = path
        self._select_tree_path(path)
        self._render_breadcrumbs()
        self._refresh_table_for_current_folder()

    def set_file_pending(
        self, file_ref_id: int, pending: bool, label: str = ""
    ) -> None:
        actions.set_file_pending(self, file_ref_id, pending, label)

    def _populate_tree(self) -> None:
        tree.populate_tree(self)

    def _handle_tree_selection_changed(self) -> None:
        tree.handle_tree_selection_changed(self)

    def _activate_tree_item(self, item, _column: int = 0) -> None:
        tree.activate_tree_item(self, item, _column)

    def _activate_tree_path(self, path: str) -> None:
        tree.activate_tree_path(self, path)

    def _select_tree_path(self, path: str) -> None:
        tree.select_tree_path(self, path)

    def _show_tree_context_menu(self, pos) -> None:
        tree.show_tree_context_menu(self, pos)

    def _on_tree_item_expanded(self, index) -> None:
        tree.on_tree_item_expanded(self, index)

    def _on_tree_item_collapsed(self, index) -> None:
        tree.on_tree_item_collapsed(self, index)

    def _refresh_table_for_current_folder(self) -> None:
        table.refresh_for_current_folder(self)

    def _selected_table_paths(self) -> list[str]:
        return table.selected_table_paths(self)

    def _sync_selected_file_from_table(self) -> None:
        table.sync_selected_file_from_table(self)

    def _activate_selected_table_item(self, item: QTableWidgetItem) -> None:
        table.activate_selected_table_item(self, item)

    def _show_table_context_menu(self, pos) -> None:
        table.show_table_context_menu(self, pos)

    def _request_import(self) -> None:
        table.request_import(self)

    def _handle_dropped_paths(self, paths: list[str]) -> None:
        table.handle_dropped_paths(self, paths)

    def _request_delete(self) -> None:
        table.request_delete(self)

    def _populate_unlocked_cards(self) -> None:
        inspector.populate_unlocked_cards(self)

    def _set_active_tab(self, name: str) -> None:
        inspector.set_active_tab(self, name)

    def _update_selection(self, path: str) -> None:
        inspector.update_selection(self, path)

    def _show_multi_selection(self, paths: list[str]) -> None:
        inspector.show_multi_selection(self, paths)

    def _clear_properties(self) -> None:
        inspector.clear_properties(self)

    def _selected_entry(self) -> FileEntry | None:
        return inspector.selected_entry(self)

    def _open_selected_file(self) -> None:
        inspector.open_selected_file(self)

    def _lock_selected_from_properties(self) -> None:
        inspector.lock_selected_from_properties(self)

    def _export_selected_from_properties(self) -> None:
        inspector.export_selected_from_properties(self)

    def _update_rename_button_state(self, paths: list[str]) -> None:
        actions.update_rename_button_state(self, paths)

    def _update_move_button_state(self, paths: list[str]) -> None:
        actions.update_move_button_state(self, paths)

    def _prompt_create_folder(self) -> None:
        actions.prompt_create_folder(self)

    def _prompt_rename(self) -> None:
        actions.prompt_rename(self)

    def _prompt_move(self) -> None:
        actions.prompt_move(self)

    def _on_cut(self, paths: list[str]) -> None:
        actions.on_cut(self, paths)

    def _on_copy(self, paths: list[str]) -> None:
        actions.on_copy(self, paths)

    def _on_paste(self) -> None:
        actions.on_paste(self)

    def _copy_virtual_path(self, path: str | None) -> None:
        actions.copy_virtual_path(self, path)

    def _emit_current_folder_changed(self) -> None:
        actions.emit_current_folder_changed(self)

    def _render_breadcrumbs(self) -> None:
        """Backwards-compatible no-op shim that just re-emits the signal."""
        actions.emit_current_folder_changed(self)
