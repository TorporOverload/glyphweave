"""Custom widgets used across the file-view: toolbar buttons, type badges,
inspector tabs, the unlocked-file card, and the drop-aware table widget."""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup import TOKENS

from .helpers import IconLabel, css, force_wrap, tinted_icon
from .models import UnlockedFile


class ImportDropTableWidget(QTableWidget):
    """``QTableWidget`` subclass that emits ``paths_dropped`` when the user
    drops local files/folders onto it."""

    paths_dropped = Signal(list)

    def __init__(self, rows: int, columns: int, parent: QWidget | None = None) -> None:
        super().__init__(rows, columns, parent)
        self.setAcceptDrops(True)
        self.setDragEnabled(True)
        self.setDragDropOverwriteMode(False)
        self._empty_label = QLabel(
            "Drop files here or use Import to add files",
            self.viewport(),
        )
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.setStyleSheet(
            f'font-family: "IBM Plex Sans"; font-size: 12px; '
            f"color: {css(TOKENS.colors.text_muted)}; background: transparent;"
        )
        self._empty_label.hide()

    def set_empty(self, is_empty: bool) -> None:
        self._empty_label.setVisible(is_empty)
        if is_empty:
            self._reposition_empty_label()

    def _reposition_empty_label(self) -> None:
        self._empty_label.resize(self.viewport().size())

    def resizeEvent(self, event):  # type: ignore[override]
        super().resizeEvent(event)
        self._reposition_empty_label()

    def dragEnterEvent(self, event):  # type: ignore[override]
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragMoveEvent(self, event):  # type: ignore[override]
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):  # type: ignore[override]
        paths: list[str] = []
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if path:
                paths.append(path)
        if paths:
            self.paths_dropped.emit(paths)


class ToolButton(QPushButton):
    """Toolbar action button with icon + label, matching the React design's
    ``.tool-btn`` style - 26px tall, transparent default, hover bg + border.
    """

    def __init__(
        self,
        icon_name: str,
        label: str,
        *,
        icon_color: QColor | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(label, parent)
        self.setObjectName("FileViewToolBtn")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFlat(True)
        self.setFixedHeight(30)
        ic_color = icon_color or TOKENS.colors.text_secondary
        self.setIcon(tinted_icon(icon_name, size=14, color=ic_color))
        self.setIconSize(QSize(14, 14))
        # Visual styling lives in section_shell.py (#FileViewToolBtn).


class TypeBadge(QLabel):
    """Compact chip showing a file's type label (DOCX, PDF, PNG, …) tinted
    with the per-extension accent colour from ``FILE_ICON_MAP``."""

    def __init__(self, text: str, accent: str, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        accent_color = QColor(accent) if accent else QColor("#5e81ac")
        bg = QColor(accent_color)
        bg.setAlpha(38)
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {css(bg)};
                color: {css(accent_color)};
                border-radius: 3px;
                padding: 1px 6px;
                font-family: "IBM Plex Mono";
                font-size: 10px;
                font-weight: 600;
                letter-spacing: 0.04em;
            }}
        """)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)


class InspectorTab(QFrame):
    """Segmented inspector tab with optional count chip
    (Properties / Unlocked). Acts like a toggle button - emits ``clicked``
    on left mousedown."""

    clicked = Signal()

    def __init__(
        self,
        label: str,
        *,
        count: int | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._label_text = label
        self._count = count
        self._active = False
        self.setObjectName("InspectorTab")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(28)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 0, 14, 0)
        layout.setSpacing(6)

        self._label = QLabel(label, self)
        layout.addWidget(self._label)

        self._chip = QLabel(self)
        self._chip.setObjectName("InspectorTabCount")
        self._chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._chip.setVisible(False)
        layout.addWidget(self._chip)

        self.set_count(count)
        self.set_active(False)

    def set_count(self, count: int | None) -> None:
        self._count = count
        if count is None or count == 0:
            self._chip.setVisible(False)
            return
        self._chip.setText(str(count))
        self._chip.setVisible(True)
        c = TOKENS.colors
        single_digit = count < 10
        if single_digit:
            self._chip.setFixedSize(16, 16)
        else:
            self._chip.setFixedHeight(16)
            self._chip.setMaximumWidth(16777215)
        padding = "0px 0px" if single_digit else "0px 5px"
        border_radius = "8px"
        self._chip.setStyleSheet(f"""
            QLabel#InspectorTabCount {{
                background-color: {css(c.text_primary)};
                color: {css(c.text_inverse)};
                border-radius: {border_radius};
                padding: {padding};
                font-family: "IBM Plex Sans";
                font-size: 10px;
                font-weight: 600;
            }}
        """)

    def set_active(self, active: bool) -> None:
        self._active = active
        c = TOKENS.colors
        if active:
            self.setStyleSheet(f"""
                QFrame#InspectorTab {{
                    background-color: {css(c.bg_base)};
                    border: 1px solid {css(TOKENS.palette.nord4)};
                    border-radius: 4px;
                }}
            """)
            self._label.setStyleSheet(
                f'font-family: "IBM Plex Sans"; font-size: 12px; '
                f"font-weight: 600; color: {css(c.text_primary)};"
            )
        else:
            self.setStyleSheet("""
                QFrame#InspectorTab {
                    background-color: transparent;
                    border: 1px solid transparent;
                    border-radius: 4px;
                }
            """)
            self._label.setStyleSheet(
                f'font-family: "IBM Plex Sans"; font-size: 12px; '
                f"font-weight: 500; color: {css(c.text_muted)};"
            )

    def mousePressEvent(self, event):  # type: ignore[override]
        super().mousePressEvent(event)
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()


class UnlockedFileCard(QFrame):
    """Card shown in the post-unlock 'Unlocked' tab.

    The whole card is clickable as a shortcut for reopening the file. The
    footer also exposes explicit Reopen and Lock icon buttons per the design.
    """

    mouse_press = None
    reopen_clicked = None  # callable(entry) -> None
    lock_clicked = None  # callable(entry) -> None

    def __init__(self, entry: UnlockedFile, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._entry = entry
        self._selected = False
        self._pending = False
        self._confirm_pending = False
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._confirm_timer = QTimer(self)
        self._confirm_timer.setSingleShot(True)
        self._confirm_timer.setInterval(3000)
        self._confirm_timer.timeout.connect(self._reset_lock_confirm)
        self._build_ui()

    def _build_ui(self) -> None:
        c = TOKENS.colors
        self.setObjectName("UnlockedFileCard")
        self.setStyleSheet(f"""
            QFrame#UnlockedFileCard {{
                background-color: {css(c.bg_base)};
                border: 1px solid {css(c.border_default)};
                border-radius: {TOKENS.radius.sm}px;
            }}
            QFrame#UnlockedFileCard:hover {{
                background-color: {css(c.bg_elevated)};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)

        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(8)
        self.icon_label = IconLabel(
            "lock-simple-open", size=14, color=c.status_warning_text, parent=self
        )
        title_row.addWidget(self.icon_label)

        self.name_label = QLabel(force_wrap(self._entry.name), self)
        self.name_label.setWordWrap(True)
        self.name_label.setMinimumWidth(0)
        self.name_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.name_label.setStyleSheet(
            f'font-family: "IBM Plex Sans"; font-size: 11px; font-weight: 700; '
            f"color: {css(c.text_primary)};"
        )
        title_row.addWidget(self.name_label, 1)
        layout.addLayout(title_row)

        display_path = self._entry.display_path or self._entry.path or "Exposed"
        self.meta_label = QLabel(force_wrap(display_path), self)
        self.meta_label.setWordWrap(True)
        self.meta_label.setMinimumWidth(0)
        self.meta_label.setStyleSheet(
            f'font-family: "IBM Plex Mono"; font-size: 11px; '
            f"color: {css(c.text_muted)};"
        )
        layout.addWidget(self.meta_label)

        actions = QHBoxLayout()
        actions.setContentsMargins(0, 2, 0, 0)
        actions.setSpacing(6)

        self._reopen_button = QPushButton("Reopen", self)
        self._reopen_button.setIcon(
            tinted_icon("folder-open", size=14, color=c.text_secondary)
        )
        self._reopen_button.setIconSize(QSize(14, 14))
        self._reopen_button.setToolTip("Reopen file")
        self._reopen_button.clicked.connect(self._on_reopen_clicked)
        actions.addWidget(self._reopen_button, 1)

        self._lock_button = QPushButton("Lock", self)
        self._lock_button.setIcon(
            tinted_icon("lock-simple", size=14, color=c.text_secondary)
        )
        self._lock_button.setIconSize(QSize(14, 14))
        self._lock_button.setToolTip("Lock file")
        self._lock_button.clicked.connect(self._on_lock_clicked)
        actions.addWidget(self._lock_button, 1)

        self._button_normal_css = f"""
            QPushButton {{
                background-color: {css(c.bg_elevated)};
                border: 1px solid {css(TOKENS.palette.nord4)};
                border-radius: 4px;
                font-family: "IBM Plex Sans";
                font-size: 11px;
                color: {css(c.text_secondary)};
            }}
            QPushButton:hover {{ background-color: {css(c.bg_base)}; }}
        """
        for button in (self._reopen_button, self._lock_button):
            button.setFixedHeight(26)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setStyleSheet(self._button_normal_css)
        layout.addLayout(actions)

    def _on_reopen_clicked(self) -> None:
        if self.reopen_clicked:
            self.reopen_clicked(self._entry)
        elif self.mouse_press:
            # Backwards-compat: fall back to the whole-card click handler
            # (which historically reopened the file).
            self.mouse_press(self._entry)

    def _on_lock_clicked(self) -> None:
        if not self._confirm_pending:
            # First press - enter "are you sure?" state.
            self._confirm_pending = True
            self._lock_button.setText("you sure?")
            c = TOKENS.colors
            self._lock_button.setStyleSheet(f"""
                QPushButton {{
                    background-color: rgba(191, 97, 106, 0.15);
                    border: 1px solid {css(c.status_error_text)};
                    border-radius: 4px;
                    font-family: "IBM Plex Sans";
                    font-size: 11px;
                    color: {css(c.status_error_text)};
                }}
                QPushButton:hover {{ background-color: rgba(191, 97, 106, 0.25); }}
            """)
            self._confirm_timer.start()
            return
        # Second press - confirmed; proceed with lock.
        self._confirm_timer.stop()
        self._reset_lock_confirm()
        if self.lock_clicked:
            self.lock_clicked(self._entry)

    def _reset_lock_confirm(self) -> None:
        """Reset the lock button back to its normal appearance."""
        self._confirm_pending = False
        self._lock_button.setText("Lock")
        self._lock_button.setStyleSheet(self._button_normal_css)

    def mousePressEvent(self, event):  # type: ignore[override]
        # Qt delivers child events first, so we only get here for the card
        # body - the action buttons handle their own clicks above.
        if self.mouse_press:
            self.mouse_press(self._entry)

    def set_selected(self, selected: bool) -> None:
        self._selected = selected
        color = (
            TOKENS.colors.focus_ring if selected else TOKENS.colors.status_warning_text
        )
        self.icon_label.setPixmap(
            tinted_icon("lock-simple-open", size=14, color=color).pixmap(14, 14)
        )

    def set_pending(self, pending: bool, label: str = "") -> None:
        self._pending = pending
        if pending:
            self.name_label.setText(label)
        else:
            self.name_label.setText(self._entry.name)
