from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QResizeEvent
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup import (
    TOKENS,
    ButtonVariant,
    Role,
    apply_button,
    apply_text_style,
    set_properties,
)

_MAX_VISIBLE_VAULTS = 5
_ROW_HEIGHT = 72
_ROW_SPACING = 10
_MODAL_H_PAD = 24
_MODAL_TOP = 28
_MODAL_BOTTOM = 24
_MODAL_WIDTH = 620


@dataclass(frozen=True, slots=True)
class VaultListEntry:
    vault_id: str
    name: str
    path: str
    last_opened: str
    highlighted: bool = False
    status: str = "ok"  # "ok" | "warn" | "locked"


class ElidedLabel(QLabel):
    def __init__(
        self,
        text: str,
        *,
        mode: Qt.TextElideMode,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._full_text = text
        self._mode = mode
        self.setWordWrap(False)
        self.setMinimumWidth(0)
        self._sync_text()

    def resizeEvent(self, event: QResizeEvent) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._sync_text()

    def _sync_text(self) -> None:
        width = max(0, self.contentsRect().width())
        if width <= 0:
            super().setText(self._full_text)
            return
        elided = self.fontMetrics().elidedText(self._full_text, self._mode, width)
        super().setText(elided)
        self.setToolTip(self._full_text if elided != self._full_text else "")


class VaultRowButton(QFrame):
    """Clickable row showing one vault's name + path + last-opened timestamp."""

    clicked = Signal()
    delete_requested = Signal()

    def __init__(self, entry: VaultListEntry, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.entry = entry
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(_ROW_HEIGHT)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        set_properties(self, role=Role.VAULT_ITEM)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.DefaultContextMenu)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 10, 18, 10)
        layout.setSpacing(14)
        # has only two columns: info + meta.

        # Text column: name + path stacked
        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(4)

        name_label = ElidedLabel(
            entry.name, mode=Qt.TextElideMode.ElideRight, parent=self
        )
        name_label.setFixedHeight(22)
        apply_text_style(name_label, TOKENS.typography.card_title)
        text_col.addWidget(name_label)

        path_label = ElidedLabel(
            entry.path, mode=Qt.TextElideMode.ElideMiddle, parent=self
        )
        path_label.setFixedHeight(18)
        apply_text_style(path_label, TOKENS.typography.caption)
        set_properties(path_label, role=Role.VAULT_PATH)
        text_col.addWidget(path_label)

        layout.addLayout(text_col, 1)

        # Timestamp on right
        if entry.last_opened:
            ts_label = QLabel(entry.last_opened, self)
            ts_label.setFixedHeight(18)
            apply_text_style(ts_label, TOKENS.typography.caption)
            set_properties(ts_label, role=Role.VAULT_TIMESTAMP)
            layout.addWidget(ts_label, 0, Qt.AlignmentFlag.AlignVCenter)
        elif entry.highlighted:
            indicator = QLabel(self)
            indicator.setFixedSize(6, 6)
            set_properties(indicator, role=Role.VAULT_INDICATOR)
            layout.addWidget(indicator, 0, Qt.AlignmentFlag.AlignVCenter)

    # Mouse + keyboard activation (QPushButton-compatible surface)

    def mousePressEvent(self, event):  # type: ignore[override]
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)

    def keyPressEvent(self, event):  # type: ignore[override]
        if event.key() in (
            Qt.Key.Key_Return,
            Qt.Key.Key_Enter,
            Qt.Key.Key_Space,
        ):
            self.clicked.emit()
            return
        super().keyPressEvent(event)

    def contextMenuEvent(self, event):  # type: ignore[override]
        menu = QMenu(self)
        delete_action = menu.addAction("Delete vault…")
        chosen = menu.exec(event.globalPos())
        if chosen is delete_action:
            self.delete_requested.emit()


class VaultListScreen(QWidget):
    create_new_vault_requested = Signal()
    vault_selected = Signal(str)
    vault_delete_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._entries: list[VaultListEntry] = []
        self._build_ui()

    def _build_ui(self) -> None:
        set_properties(self, role=Role.VAULT_LIST)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(0)

        # Top-left breadcrumb label
        intro = QLabel("choose a vault", self)
        apply_text_style(intro, TOKENS.typography.caption)
        set_properties(intro, role=Role.VAULT_INTRO)
        root.addWidget(intro, 0, Qt.AlignmentFlag.AlignLeft)

        root.addStretch(1)

        # Centered modal card
        self.modal = QFrame(self)
        set_properties(self.modal, role=Role.VAULT_LIST_MODAL)
        self.modal.setFixedWidth(_MODAL_WIDTH)
        root.addWidget(self.modal, 0, Qt.AlignmentFlag.AlignHCenter)

        modal_layout = QVBoxLayout(self.modal)
        modal_layout.setContentsMargins(
            _MODAL_H_PAD, _MODAL_TOP, _MODAL_H_PAD, _MODAL_BOTTOM
        )
        modal_layout.setSpacing(0)

        # Title inside modal
        title = QLabel("Your vaults", self.modal)
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        apply_text_style(title, TOKENS.typography.page_title)
        modal_layout.addWidget(title)

        modal_layout.addSpacing(4)

        # Subtitle inside modal
        subtitle = QLabel("Select a vault to unlock", self.modal)
        subtitle.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        apply_text_style(subtitle, TOKENS.typography.mono)
        set_properties(subtitle, role=Role.VAULT_SUBTITLE)
        modal_layout.addWidget(subtitle)

        modal_layout.addSpacing(16)

        # Scroll area for vault rows
        self.scroll_area = QScrollArea(self.modal)
        self.scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.scroll_area.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        modal_layout.addWidget(self.scroll_area)

        self.scroll_content = QWidget(self.scroll_area)
        self.scroll_area.setWidget(self.scroll_content)

        self.rows_layout = QVBoxLayout(self.scroll_content)
        self.rows_layout.setContentsMargins(0, 0, 0, 0)
        self.rows_layout.setSpacing(_ROW_SPACING)

        modal_layout.addSpacing(12)

        # Create button inside modal - full width, bordered
        self.create_button = QPushButton("+ Create a new vault", self.modal)
        self.create_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.create_button.setFixedHeight(40)
        apply_button(self.create_button, ButtonVariant.GHOST)
        self.create_button.clicked.connect(self.create_new_vault_requested.emit)
        modal_layout.addWidget(self.create_button)

        root.addStretch(1)

    def set_vaults(self, entries: Sequence[VaultListEntry]) -> None:
        self._entries = list(entries)
        while self.rows_layout.count():
            item = self.rows_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        for entry in self._entries:
            row = VaultRowButton(entry, self.scroll_content)
            row.clicked.connect(
                lambda vault_id=entry.vault_id: self.vault_selected.emit(vault_id)
            )
            row.delete_requested.connect(
                lambda vault_id=entry.vault_id: self.vault_delete_requested.emit(
                    vault_id
                )
            )
            self.rows_layout.addWidget(row)

        self.rows_layout.addStretch(1)
        self._sync_modal_size()

    def focus_first_vault(self) -> None:
        for index in range(self.rows_layout.count()):
            widget = self.rows_layout.itemAt(index).widget()
            if isinstance(widget, VaultRowButton):
                widget.setFocus()
                return
        self.create_button.setFocus()

    def entry_for_id(self, vault_id: str) -> VaultListEntry | None:
        for entry in self._entries:
            if entry.vault_id == vault_id:
                return entry
        return None

    def _sync_modal_size(self) -> None:
        count = len(self._entries)
        visible_count = max(1, min(count, _MAX_VISIBLE_VAULTS))
        rows_height = (visible_count * _ROW_HEIGHT) + (
            max(0, visible_count - 1) * _ROW_SPACING
        )
        self.scroll_area.setFixedHeight(rows_height)

        title_h = 32  # page_title
        subtitle_h = 20
        create_btn_h = 40
        total_h = (
            _MODAL_TOP
            + title_h
            + 4
            + subtitle_h
            + 16
            + rows_height
            + 12
            + create_btn_h
            + _MODAL_BOTTOM
        )
        self.modal.setFixedHeight(total_h)

        needs_scroll = count > _MAX_VISIBLE_VAULTS
        self.scroll_area.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
            if needs_scroll
            else Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )


__all__ = ["VaultListEntry", "VaultListScreen"]
