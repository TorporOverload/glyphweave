"""Left sidebar panel that hosts the file tree.

The vault name is rendered as the topmost tree row. Clicking that row fires
``home_requested`` so the file view jumps back to the vault root instead
of any sub-folder selection."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.screens.file_view.models import _TREE_PATH_ROLE


class VaultTreePanel(QWidget):
    """Left panel containing the vault file tree."""

    file_open_requested = Signal(int)
    home_requested = Signal()

    def __init__(
        self,
        tree_widget: QWidget,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._tree_widget = tree_widget
        self._vault_name: str = ""
        # Sidebar width 240px. gives long folder names enough room without
        # crowding the content area.
        self.setFixedWidth(240)
        self.setObjectName("VaultTreePanel")
        self._build_ui()
        self._wire_tree_signals()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        tree_container = QFrame(self)
        tree_container.setObjectName("VaultTreeContainer")
        tree_layout = QVBoxLayout(tree_container)
        tree_layout.setContentsMargins(8, 8, 4, 8)
        tree_layout.setSpacing(0)
        tree_layout.addWidget(self._tree_widget)
        layout.addWidget(tree_container, 1)

    def _wire_tree_signals(self) -> None:
        """Make a click on the vault-root row jump to the vault root."""
        if isinstance(self._tree_widget, QTreeWidget):
            # itemClicked fires AFTER currentItemChanged, so navigation
            # logic (in screens.file_view.tree) has already short-circuited
            # for the "/" path by the time we get here.
            self._tree_widget.itemClicked.connect(self._on_tree_item_clicked)

    def _on_tree_item_clicked(self, item: QTreeWidgetItem, _column: int) -> None:
        if item is None:
            return
        path = item.data(0, _TREE_PATH_ROLE)
        if path == "/":
            # Vault root row navigates back to the top-level file listing
            # (vault root). Vault switching lives in the menu and
            # vault-list screen, not on the tree row.
            self.home_requested.emit()

    def set_vault_name(self, name: str) -> None:
        """Update the root tree row to show the new vault name.

        The actual root item is created/recreated by
        :func:`screens.file_view.tree.populate_tree`; this method just
        keeps it in sync when only the name changes between repopulations.
        """
        self._vault_name = name
        if isinstance(self._tree_widget, QTreeWidget):
            if self._tree_widget.topLevelItemCount() > 0:
                root = self._tree_widget.topLevelItem(0)
                if root is not None and root.data(0, _TREE_PATH_ROLE) == "/":
                    root.setText(0, name or "Vault")
