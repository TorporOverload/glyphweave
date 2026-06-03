"""Command-palette style overlay used to host the search screen."""

from __future__ import annotations

from PySide6.QtCore import QEvent, Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup import TOKENS

from ...screens.search import SearchScreen
from .helpers import css_color


class SearchOverlay(QDialog):
    """Dimmed overlay containing a compact search command palette."""

    search_requested = Signal(str)

    # Heights chosen to match the SearchScreen layout: search bar (58) +
    # filter row (50) + frame border. The expanded form keeps the original
    # 460 so the results scroll has room to breathe.
    _COMPACT_HEIGHT = 116
    _EXPANDED_HEIGHT = 460
    _OVERLAY_WIDTH = 890

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setModal(False)
        self.setFixedSize(self._OVERLAY_WIDTH, self._COMPACT_HEIGHT)
        self._search_screen: SearchScreen | None = None
        self.search_input: QLineEdit | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        self.setObjectName("SearchOverlayDialog")
        self.setStyleSheet(f"""
            QDialog#SearchOverlayDialog {{
                background: transparent;
            }}
            QFrame#SearchPaletteFrame {{
                background-color: {css_color(TOKENS.colors.bg_panel)};
                border: 1px solid {css_color(TOKENS.colors.border_default)};
                border-radius: {TOKENS.radius.md}px;
            }}
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.palette_frame = QFrame(self)
        self.palette_frame.setObjectName("SearchPaletteFrame")

        self.palette_layout = QVBoxLayout(self.palette_frame)
        self.palette_layout.setContentsMargins(0, 0, 0, 0)
        self.palette_layout.setSpacing(0)

        root.addWidget(self.palette_frame)

    def set_search_screen(self, screen: SearchScreen) -> None:
        """Set the embedded search screen and use its input as overlay input."""
        self._search_screen = screen
        if self.palette_layout.indexOf(screen) == -1:
            self.palette_layout.addWidget(screen)
        screen.setVisible(True)
        self.search_input = screen._search_input
        screen.compact_changed.connect(self._on_compact_changed)

    def _on_compact_changed(self, compact: bool) -> None:
        """Grow / shrink the dialog so an empty query doesn't leave a 320px
        ghost area below the search input."""
        target = self._COMPACT_HEIGHT if compact else self._EXPANDED_HEIGHT
        if self.height() == target:
            return
        self.setFixedSize(self._OVERLAY_WIDTH, target)
        # Re-anchor near the parent's top so the resize doesn't slide the
        # dialog off-centre relative to where the user invoked it.
        parent = self.parentWidget()
        if parent is not None:
            x = max(0, (parent.width() - self.width()) // 2)
            parent_top_left = parent.mapToGlobal(parent.rect().topLeft())
            self.move(parent_top_left.x() + x, parent_top_left.y() + 22)

    def inject_service(self, service) -> None:
        """Inject ``VaultService`` into the search screen."""
        if self._search_screen and hasattr(self._search_screen, "set_service"):
            self._search_screen.set_service(service)

    def showEvent(self, event) -> None:
        parent = self.parentWidget()
        if parent is not None:
            x = max(0, (parent.width() - self.width()) // 2)
            y = 22
            parent_top_left = parent.mapToGlobal(parent.rect().topLeft())
            self.move(parent_top_left.x() + x, parent_top_left.y() + y)
        super().showEvent(event)
        if self.search_input is not None:
            self.search_input.setFocus()
            self.search_input.selectAll()

    def event(self, event) -> bool:
        if event.type() == QEvent.Type.WindowDeactivate:
            if QApplication.activePopupWidget() is None:
                self.accept()
                return True
        return super().event(event)

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key.Key_Escape:
            self.accept()
        else:
            super().keyPressEvent(event)
