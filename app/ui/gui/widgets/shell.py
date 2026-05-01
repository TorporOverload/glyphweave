from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup.theme import (
    apply_button,
    apply_sidebar_item_style,
    apply_text_style,
    set_tone,
)
from app.ui.gui.setup.tokens import ButtonVariant, Role, StatusKey, TOKENS, Tone
from .common import StatusBadge


class SidebarNav(QWidget):
    destination_selected = Signal(str)

    def __init__(
        self,
        *,
        current: str = "Dashboard",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("SidebarNav")
        self.setMinimumWidth(TOKENS.sizes.sidebar_width_min)
        self.setMaximumWidth(TOKENS.sizes.sidebar_width_max)
        self._buttons: dict[str, QPushButton] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            TOKENS.spacing.xl,
            TOKENS.spacing.xl,
            TOKENS.spacing.xl,
            TOKENS.spacing.xl,
        )
        layout.setSpacing(TOKENS.spacing.lg)

        brand = QLabel("GlyphWeave", self)
        apply_text_style(brand, TOKENS.typography.section_title)
        layout.addWidget(brand)

        vault = QLabel("Personal Archive", self)
        apply_text_style(vault, TOKENS.typography.body_secondary)
        set_tone(vault, Tone.MUTED)
        layout.addWidget(vault)

        nav_layout = QVBoxLayout()
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(TOKENS.spacing.sm)

        for label in (
            "Dashboard",
            "Library",
            "Search",
            "Vaults",
            "Sync",
            "Backups",
            "Settings",
        ):
            button = QPushButton(label, self)
            apply_sidebar_item_style(button, active=label == current)
            button.clicked.connect(
                lambda checked=False, name=label: self._handle_click(name)
            )
            nav_layout.addWidget(button)
            self._buttons[label] = button

        layout.addLayout(nav_layout)
        layout.addStretch(1)

        utility = QPushButton("Lock vault", self)
        apply_button(utility, ButtonVariant.SECONDARY)
        layout.addWidget(utility)
        self.lock_button = utility

    def _handle_click(self, name: str) -> None:
        self.set_current(name)
        self.destination_selected.emit(name)

    def set_current(self, name: str) -> None:
        for label, button in self._buttons.items():
            apply_sidebar_item_style(button, active=label == name)


class TopBar(QWidget):
    lock_requested = Signal()

    def __init__(
        self,
        title: str,
        *,
        status: StatusKey = StatusKey.SYNCED,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("TopBar")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(
            TOKENS.spacing.xl,
            TOKENS.spacing.lg,
            TOKENS.spacing.xl,
            TOKENS.spacing.lg,
        )
        layout.setSpacing(TOKENS.spacing.md)

        self.title_label = QLabel(title, self)
        apply_text_style(self.title_label, TOKENS.typography.page_title)
        layout.addWidget(self.title_label)
        layout.addStretch(1)

        self.search_button = QPushButton("Search", self)
        apply_button(self.search_button, ButtonVariant.GHOST)
        layout.addWidget(self.search_button)

        self.import_button = QPushButton("Import", self)
        apply_button(self.import_button, ButtonVariant.PRIMARY)
        layout.addWidget(self.import_button)

        self.status_badge = StatusBadge(status, self)
        layout.addWidget(self.status_badge, 0, Qt.AlignmentFlag.AlignVCenter)

        self.lock_button = QPushButton("Lock vault", self)
        apply_button(self.lock_button, ButtonVariant.SECONDARY)
        self.lock_button.clicked.connect(self.lock_requested.emit)
        layout.addWidget(self.lock_button)

    def set_title(self, title: str) -> None:
        self.title_label.setText(title)

    def set_status(self, status: StatusKey) -> None:
        self.status_badge.set_status(status)


class AppShell(QWidget):
    """Post-unlock container that hosts the SidebarNav and a content stack."""

    vault_switch_requested = Signal()
    lock_requested = Signal()

    def __init__(
        self,
        file_view: QWidget,
        dashboard_screen: QWidget,
        *,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("AppShell")

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.sidebar = SidebarNav(current="Library", parent=self)
        self.sidebar.destination_selected.connect(self._handle_nav)
        self.sidebar.lock_button.clicked.connect(self.lock_requested.emit)
        root.addWidget(self.sidebar)

        self.content_stack = QStackedWidget(self)
        root.addWidget(self.content_stack, 1)

        self.file_view = file_view
        self.dashboard = dashboard_screen

        # Stub screens — full implementation deferred to later tasks.
        self.search_screen = QWidget(self)
        _search_label = QLabel("Search — coming soon", self.search_screen)

        self.sync_screen = QWidget(self)
        _sync_label = QLabel("Sync — coming soon", self.sync_screen)

        self.content_stack.addWidget(self.file_view)
        self.content_stack.addWidget(self.dashboard)
        self.content_stack.addWidget(self.search_screen)
        self.content_stack.addWidget(self.sync_screen)

        # Default landing screen.
        self.content_stack.setCurrentWidget(self.file_view)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_vault_data(self, payload: object) -> None:
        """Forward vault payload to the FileViewScreen."""
        # Accept the FileViewPayload dataclass defined in the main window module
        # without creating a hard import cycle.  Extract attributes by name.
        vault_name = getattr(payload, "vault_name", "")
        entries = getattr(payload, "entries", [])
        unlocked_files = getattr(payload, "unlocked_files", [])
        self.file_view.set_vault_data(
            vault_name=vault_name,
            entries=entries,
            unlocked_files=unlocked_files,
        )

    def navigate(self, name: str) -> None:
        """Switch the content area to the named screen."""
        screen_map: dict[str, QWidget] = {
            "Library": self.file_view,
            "Dashboard": self.dashboard,
            "Search": self.search_screen,
            "Sync": self.sync_screen,
        }
        widget = screen_map.get(name)
        if widget is not None:
            self.content_stack.setCurrentWidget(widget)
            self.sidebar.set_current(name)

    def clear(self) -> None:
        """Reset shell state before the vault is locked."""
        self.sidebar.set_current("Library")
        self.content_stack.setCurrentWidget(self.file_view)

    # ------------------------------------------------------------------
    # Internal slots
    # ------------------------------------------------------------------

    def _handle_nav(self, name: str) -> None:
        if name == "Vaults":
            self.vault_switch_requested.emit()
            return
        # Non-navigable stubs — ignore silently for now.
        if name in ("Backups", "Settings"):
            return
        self.navigate(name)
