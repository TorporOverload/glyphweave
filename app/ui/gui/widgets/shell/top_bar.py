"""Top navigation bar."""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QWidget,
)

from app.ui.gui.setup import TOKENS, StatusKey


class _SearchLineEdit(QLineEdit):

    focused = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)

    def mousePressEvent(self, event):  # type: ignore[override]
        super().mousePressEvent(event)
        self.focused.emit()


class TopBar(QWidget):
    """Top navigation bar with brand wordmark, search bar, and sync bell."""

    search_focused = Signal()
    sync_bell_clicked = Signal()

    def __init__(self, *, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._vault_name: str = ""
        self._sync_status: StatusKey = StatusKey.SYNCED
        self._build_ui()

    def _build_ui(self) -> None:
        self.setObjectName("TopBar")
        self.setFixedHeight(56)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 0, 20, 0)
        layout.setSpacing(14)

        # Brand wordmark.
        brand = QLabel("glyphweave", self)
        brand.setObjectName("TopBarBrand")
        layout.addWidget(brand)

        # Search bar. Real QLineEdit so it gets a proper focus ring and
        # cursor; clicking/focusing opens the search overlay instead of
        # accepting keystrokes here directly.
        self.search_input = _SearchLineEdit(self)
        self.search_input.setObjectName("TopBarSearch")
        self.search_input.setFixedHeight(34)
        self.search_input.setReadOnly(True)
        self.search_input.setPlaceholderText("Search files, content, paths…")
        self.search_input.setCursor(Qt.CursorShape.IBeamCursor)
        self.search_input.focused.connect(self.search_focused.emit)

        # Ctrl+K hint chip overlaid inside the line edit's right padding.
        self._search_hint = QLabel("Ctrl+K", self.search_input)
        self._search_hint.setObjectName("TopBarSearchHint")
        self._search_hint.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._search_hint.adjustSize()
        # Reserve right-side padding for the hint chip.
        self.search_input.setTextMargins(0, 0, 64, 0)
        self.search_input.installEventFilter(self)

        layout.addWidget(self.search_input, 1)

        # Bell button (sync / conflicts).
        from app.ui.gui.setup.icons import tinted_icon

        self.bell_button = QPushButton(self)
        self.bell_button.setObjectName("TopBarBell")
        self.bell_button.setFixedSize(34, 34)
        self.bell_button.setFlat(True)
        self.bell_button.setIcon(
            tinted_icon("bell", size=16, color=TOKENS.colors.text_primary)
        )
        self.bell_button.setIconSize(QSize(16, 16))
        self.bell_button.clicked.connect(self.sync_bell_clicked.emit)
        layout.addWidget(self.bell_button)

        # Red unread dot painted on top of the bell. Hidden until there is
        # at least one active sync conflict; positioned in the upper-right
        # corner of the bell button via _reposition_bell_dot.
        self._bell_dot = QLabel(self.bell_button)
        self._bell_dot.setObjectName("TopBarBellDot")
        self._bell_dot.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents
        )
        self._bell_dot.setFixedSize(8, 8)
        self._bell_dot.setStyleSheet(
            "QLabel#TopBarBellDot { background-color: #BF616A; "
            "border-radius: 4px; }"
        )
        self._bell_dot.hide()
        self._reposition_bell_dot()

    def eventFilter(self, obj, event):  # type: ignore[override]
        # Reposition the ctrl + k hint whenever the search input resizes.
        from PySide6.QtCore import QEvent

        if obj is self.search_input and event.type() == QEvent.Type.Resize:
            self._reposition_search_hint()
        return super().eventFilter(obj, event)

    def _reposition_search_hint(self) -> None:
        if not self._search_hint:
            return
        margin = 10
        x = self.search_input.width() - self._search_hint.width() - margin
        y = (self.search_input.height() - self._search_hint.height()) // 2
        self._search_hint.move(max(0, x), max(0, y))

    def _reposition_bell_dot(self) -> None:
        if not hasattr(self, "_bell_dot"):
            return
        # Anchor the dot in the upper-right of the 34×34 bell button with
        # a 6px inset so it sits on top of the bell glyph.
        x = self.bell_button.width() - self._bell_dot.width() - 6
        self._bell_dot.move(max(0, x), 6)

    def set_conflict_count(self, count: int) -> None:
        """Show / hide the red dot on the bell.

        The dot is purely an indicator. The bell button click handler is
        responsible for opening the conflict-resolution flow.
        """
        if hasattr(self, "_bell_dot"):
            self._bell_dot.setVisible(count > 0)
            self.bell_button.setToolTip(
                f"{count} unresolved sync conflict"
                + ("s" if count != 1 else "")
                if count > 0
                else "No sync conflicts"
            )

    def set_vault_name(self, name: str) -> None:
        self._vault_name = name

    def set_sync_status(self, status: StatusKey) -> None:
        from app.ui.gui.setup.icons import tinted_icon

        self._sync_status = status
        if status == StatusKey.UNLOCK_ERROR:
            icon_name, color = "warning", TOKENS.colors.status_error_text
        elif status == StatusKey.SYNCING:
            icon_name, color = "arrows-clockwise", TOKENS.colors.text_primary
        elif status == StatusKey.CONFLICT:
            icon_name, color = "warning", TOKENS.colors.status_warning_text
        else:
            icon_name, color = "bell", TOKENS.colors.text_primary
        self.bell_button.setIcon(tinted_icon(icon_name, size=14, color=color))
        self.bell_button.setIconSize(QSize(14, 14))

    def clear_vault_name(self) -> None:
        self._vault_name = ""
