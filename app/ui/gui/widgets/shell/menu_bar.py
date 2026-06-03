"""Application menu bar (File / Vault / Edit / View / Help) with the
right-corner ``vault unlocked`` / ``vault locked`` status pill."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMenu,
    QMenuBar,
    QWidget,
)


class MenuBar(QMenuBar):
    """Application menu bar with File, Vault, Edit, View, Help.

    Items that require an unlocked vault (Import, Export, Lock, Sync Now,
    Find) auto-disable until ``set_vault_unlocked(True)`` is called.
    """

    new_vault_requested = Signal()
    vault_switch_requested = Signal()
    import_requested = Signal()
    export_requested = Signal()
    exit_requested = Signal()
    lock_requested = Signal()
    sync_now_requested = Signal()
    recovery_phrase_requested = Signal()
    find_in_vault_requested = Signal()
    preferences_requested = Signal()
    refresh_requested = Signal()
    documentation_requested = Signal()
    about_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setNativeMenuBar(False)
        self._unlock_actions: list[QAction] = []
        self._build_menus()
        self._status_pill = _MenuStatusPill(self)
        self.setCornerWidget(self._status_pill, Qt.Corner.TopRightCorner)
        self.set_vault_unlocked(False)

    def _build_menus(self) -> None:
        file_menu = self.addMenu("&File")
        self._add(file_menu, "&New Vault…", self.new_vault_requested, "Ctrl+N")
        self._add(
            file_menu, "&Open Vault…", self.vault_switch_requested, "Ctrl+O"
        )
        file_menu.addSeparator()
        self._add(
            file_menu,
            "&Import…",
            self.import_requested,
            "Ctrl+I",
            needs_unlock=True,
        )
        self._add(
            file_menu,
            "&Export…",
            self.export_requested,
            "Ctrl+E",
            needs_unlock=True,
        )
        file_menu.addSeparator()
        self._add(file_menu, "E&xit", self.exit_requested, "Ctrl+Q")

        vault_menu = self.addMenu("&Vault")
        self._add(vault_menu, "&Switch Vault…", self.vault_switch_requested)
        self._add(
            vault_menu,
            "&Lock Vault",
            self.lock_requested,
            "Ctrl+L",
            needs_unlock=True,
        )
        vault_menu.addSeparator()
        self._add(
            vault_menu,
            "S&ync Now",
            self.sync_now_requested,
            "Ctrl+R",
            needs_unlock=True,
        )
        vault_menu.addSeparator()
        self._add(
            vault_menu, "&Recovery Phrase…", self.recovery_phrase_requested,
            needs_unlock=True
        )

        edit_menu = self.addMenu("&Edit")
        self._add(
            edit_menu,
            "&Find in Vault…",
            self.find_in_vault_requested,
            "Ctrl+K",
            needs_unlock=True,
        )
        edit_menu.addSeparator()
        self._add(
            edit_menu, "&Preferences…", self.preferences_requested, "Ctrl+,"
        )

        view_menu = self.addMenu("&View")
        self._add(view_menu, "&Refresh", self.refresh_requested, "F5")

        help_menu = self.addMenu("&Help")
        self._add(help_menu, "&Documentation", self.documentation_requested)
        help_menu.addSeparator()
        self._add(help_menu, "&About Glyphweave", self.about_requested)

    def _add(
        self,
        menu: QMenu,
        label: str,
        signal: Signal,
        shortcut: str | None = None,
        *,
        needs_unlock: bool = False,
    ) -> QAction:
        action = QAction(label, self)
        if shortcut is not None:
            action.setShortcut(QKeySequence(shortcut))
        action.triggered.connect(signal.emit)
        menu.addAction(action)
        if needs_unlock:
            self._unlock_actions.append(action)
        return action

    def set_vault_unlocked(self, unlocked: bool) -> None:
        """Enable/disable items that require an unlocked vault, and update
        the corner status pill."""
        for action in self._unlock_actions:
            action.setEnabled(unlocked)
        self._status_pill.set_unlocked(unlocked)


class _MenuStatusPill(QWidget):
    """Right-corner pill showing 'vault unlocked' / 'vault locked'."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("menubarStatus")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 0, 10, 0)
        layout.setSpacing(6)
        self._label = QLabel(self)
        self._label.setObjectName("menubarStatusText")
        layout.addWidget(self._label)

    def set_unlocked(self, unlocked: bool) -> None:
        self._label.setText(
            "vault unlocked" if unlocked else "vault locked"
        )
