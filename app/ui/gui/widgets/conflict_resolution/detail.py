"""Detail-pane builder for the conflict resolution dialog.

Produces a scrollable widget for the right column: file tile header,
reason banner, versions block, properties grid, and the action ladder.
The ladder buttons are exposed as attributes so the dialog can wire them.
"""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.services.models import SyncConflictInfo
from app.ui.gui.setup import TOKENS

from .helpers import format_datetime


_EYEBROW_CSS = (
    'font-family: "IBM Plex Mono"; font-size: 10px;'
    " letter-spacing: 0.06em; color: #6B7383;"
)
_KEY_CSS = (
    'font-family: "IBM Plex Mono"; font-size: 10px;'
    " letter-spacing: 0.04em; color: #88909F;"
)
_VALUE_CSS = (
    'font-family: "IBM Plex Mono"; font-size: 11px; color: #2E3440;'
)


class _ActionRow(QPushButton):
    """Full-width ladder button: leading icon + title + sub-label."""

    def __init__(
        self,
        icon_name: str,
        title: str,
        subtitle: str,
        *,
        variant: str = "neutral",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        from app.ui.gui.setup.icons import tinted_icon

        self.setObjectName("ConflictActionRow")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFlat(True)
        self.setMinimumHeight(50)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        if variant == "danger":
            icon_color = TOKENS.colors.status_error_text
            border = "#E5C0C5"
            hover_bg = "#FAF0F1"
        elif variant == "primary":
            icon_color = TOKENS.colors.focus_ring
            border = "#C5D2E2"
            hover_bg = "#EEF2F8"
        else:
            icon_color = TOKENS.colors.text_secondary
            border = "#D0D6E0"
            hover_bg = "#F1F4F8"

        self.setStyleSheet(
            f"QPushButton#ConflictActionRow {{"
            f" background-color: #FFFFFF; border: 1px solid {border};"
            f" border-radius: 6px; padding: 0px; text-align: left;"
            f"}}"
            f"QPushButton#ConflictActionRow:hover {{ background-color: {hover_bg}; }}"
            f"QPushButton#ConflictActionRow:disabled {{"
            f" background-color: #F4F6FA; color: #B8C0CC;"
            f"}}"
        )
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(10)

        icon_lbl = QLabel(self)
        icon_lbl.setPixmap(tinted_icon(icon_name, size=14, color=icon_color).pixmap(14, 14))
        icon_lbl.setFixedSize(QSize(16, 16))
        layout.addWidget(icon_lbl, 0, Qt.AlignmentFlag.AlignVCenter)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(1)

        title_lbl = QLabel(title, self)
        title_lbl.setStyleSheet(
            'font-family: "IBM Plex Sans"; font-size: 12px;'
            " font-weight: 600; color: #2E3440;"
        )
        sub_lbl = QLabel(subtitle, self)
        sub_lbl.setStyleSheet(
            'font-family: "IBM Plex Mono"; font-size: 10px; color: #6B7383;'
        )
        text_col.addWidget(title_lbl)
        text_col.addWidget(sub_lbl)
        layout.addLayout(text_col, 1)


class DetailPane(QWidget):
    """Right pane of the conflict dialog. Stays in empty mode until
    ``set_conflict`` is called with a selected record.
    """

    open_archived_requested = Signal(str)  # archived virtual path

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ConflictDetailPane")
        self._conflict: SyncConflictInfo | None = None
        self._device_alias_resolver: Callable[[str], str | None] | None = None
        self._build_ui()
        self._show_empty_state()

    # Public API

    def set_device_alias_resolver(
        self, resolver: Callable[[str], str | None]
    ) -> None:
        self._device_alias_resolver = resolver

    def selected_conflict(self) -> SyncConflictInfo | None:
        return self._conflict

    def set_conflict(self, conflict: SyncConflictInfo | None) -> None:
        self._conflict = conflict
        if conflict is None:
            self._show_empty_state()
        else:
            self._show_conflict_state(conflict)

    # Build

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        self._content = QWidget()
        self._content_layout = QVBoxLayout(self._content)
        self._content_layout.setContentsMargins(14, 14, 14, 16)
        self._content_layout.setSpacing(10)
        scroll.setWidget(self._content)
        outer.addWidget(scroll)

    def _clear_content(self) -> None:
        while self._content_layout.count():
            item = self._content_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.hide()
                widget.deleteLater()

    def _show_empty_state(self) -> None:
        self._clear_content()
        label = QLabel(
            "No conflict selected.\n\n"
            "Pick a conflict on the left to review its details\n"
            "and choose how to resolve it.",
            self._content,
        )
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setWordWrap(True)
        label.setStyleSheet(
            'font-family: "IBM Plex Mono"; font-size: 11px; color: #88909F;'
        )
        self._content_layout.addStretch(1)
        self._content_layout.addWidget(label)
        self._content_layout.addStretch(2)

    def _show_conflict_state(self, conflict: SyncConflictInfo) -> None:
        self._clear_content()
        is_active = conflict.status == "active"

        # 1. Eyebrow row
        self._content_layout.addLayout(self._build_eyebrow_row(conflict))

        # 2. File tile
        self._content_layout.addWidget(self._build_file_tile(conflict))

        # 3. Reason banner
        self._content_layout.addWidget(self._build_reason_banner(conflict))

        # 4. VERSIONS block
        if is_active:
            self._content_layout.addWidget(self._build_divider())
            self._content_layout.addWidget(self._build_versions_block(conflict))

        # 5. PROPERTIES
        self._content_layout.addWidget(self._build_divider())
        self._content_layout.addWidget(self._build_properties(conflict))

        # 6. ACTIONS
        self._content_layout.addWidget(self._build_divider())
        self._content_layout.addWidget(self._build_actions(conflict, is_active))

        self._content_layout.addStretch(1)
    
    # Section builders
    
    def _build_eyebrow_row(self, conflict: SyncConflictInfo) -> QHBoxLayout:
        is_active = conflict.status == "active"
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        if is_active:
            eyebrow_text = "CONFLICT · ACTIVE"
            dot_color = "#BF616A"
        elif conflict.status == "resolved":
            eyebrow_text = "RESOLVED · RESTORED"
            dot_color = "#5E81AC"
        elif conflict.status == "deleted":
            eyebrow_text = "RESOLVED · DELETED"
            dot_color = "#88909F"
        else:
            eyebrow_text = "CONFLICT"
            dot_color = "#88909F"

        eyebrow = QLabel(eyebrow_text, self._content)
        eyebrow.setStyleSheet(_EYEBROW_CSS)
        layout.addWidget(eyebrow)
        layout.addStretch(1)

        dot = QLabel(self._content)
        dot.setFixedSize(8, 8)
        dot.setStyleSheet(f"background-color: {dot_color}; border-radius: 4px;")
        layout.addWidget(dot, 0, Qt.AlignmentFlag.AlignVCenter)
        return layout

    def _build_file_tile(self, conflict: SyncConflictInfo) -> QWidget:
        from app.ui.gui.setup.icons import tinted_icon

        is_folder = conflict.node_kind == "folder"
        tile = QPushButton(self._content)
        tile.setObjectName("CfFileTile")
        tile.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        tile.setFlat(True)
        tile.setCursor(Qt.CursorShape.PointingHandCursor)
        tile.setStyleSheet(
            "QPushButton#CfFileTile {"
            " background-color: #F4F6FA; border: 1px solid #C0C9D6;"
            " border-radius: 5px; padding: 0px; text-align: left;"
            "}"
            "QPushButton#CfFileTile:hover {"
            " background-color: #ECEFF4; border-color: #A8B4C4;"
            "}"
        )
        tile_layout = QHBoxLayout(tile)
        tile_layout.setContentsMargins(10, 9, 10, 9)
        tile_layout.setSpacing(8)

        tile_icon = QLabel(tile)
        tile_icon.setPixmap(
            tinted_icon(
                "folder-notch" if is_folder else "file-text",
                size=14,
                color=TOKENS.colors.status_error_text,
            ).pixmap(14, 14)
        )
        tile_icon.setFixedSize(16, 16)
        tile_layout.addWidget(tile_icon, 0, Qt.AlignmentFlag.AlignVCenter)

        tile_name = QLabel(conflict.archived_name or "(unnamed)", tile)
        tile_name.setStyleSheet(
            'font-family: "IBM Plex Mono"; font-size: 13px;'
            " font-weight: 700; color: #2E3440;"
        )
        tile_name.setWordWrap(False)
        tile_layout.addWidget(tile_name, 1)

        tile_arrow = QLabel("↗", tile)
        tile_arrow.setStyleSheet('color: #88909F; font-size: 11px;')
        tile_layout.addWidget(tile_arrow, 0, Qt.AlignmentFlag.AlignVCenter)

        if conflict.archived_virtual_path:
            archived_path = conflict.archived_virtual_path
            tile.clicked.connect(
                lambda _checked=False, p=archived_path: self.open_archived_requested.emit(p)
            )

        return tile

    def _build_reason_banner(self, conflict: SyncConflictInfo) -> QWidget:
        from app.ui.gui.setup.icons import tinted_icon

        banner = QFrame(self._content)
        banner.setStyleSheet(
            "QFrame { background-color: #FAEEEF; border: 1px solid #E5C0C5;"
            " border-radius: 5px; }"
        )
        layout = QHBoxLayout(banner)
        layout.setContentsMargins(9, 8, 9, 8)
        layout.setSpacing(8)

        icon_lbl = QLabel(banner)
        icon_lbl.setPixmap(
            tinted_icon("warning", size=13, color=TOKENS.colors.status_error_text).pixmap(13, 13)
        )
        icon_lbl.setFixedSize(15, 15)
        layout.addWidget(icon_lbl, 0, Qt.AlignmentFlag.AlignVCenter)

        text = conflict.reason_text or conflict.reason_code or "Unknown conflict reason."
        reason_lbl = QLabel(text, banner)
        reason_lbl.setStyleSheet(
            'font-family: "IBM Plex Sans"; font-size: 11px;'
            " line-height: 1.45; color: #5A2027;"
        )
        reason_lbl.setWordWrap(True)
        layout.addWidget(reason_lbl, 1)
        return banner

    def _build_versions_block(self, conflict: SyncConflictInfo) -> QWidget:
        container = QWidget(self._content)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        eyebrow = QLabel("VERSIONS", container)
        eyebrow.setStyleSheet(_EYEBROW_CSS)
        layout.addWidget(eyebrow)

        grid = QFrame(container)
        grid_layout = QHBoxLayout(grid)
        grid_layout.setContentsMargins(0, 0, 0, 0)
        grid_layout.setSpacing(6)

        grid_layout.addWidget(
            self._build_version_card(
                "ARCHIVED",
                format_datetime(conflict.created_at),
                danger=True,
                parent=container,
            ),
            1,
        )
        grid_layout.addWidget(
            self._build_version_card(
                "LIVE",
                "current version",
                danger=False,
                parent=container,
            ),
            1,
        )
        layout.addWidget(grid)
        return container

    def _build_version_card(
        self,
        tag: str,
        timestamp_text: str,
        *,
        danger: bool,
        parent: QWidget,
    ) -> QWidget:
        card = QFrame(parent)
        card.setObjectName("CfVersionCard")
        card.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        card.setStyleSheet(
            "QFrame#CfVersionCard {"
            " background-color: #F4F6FA; border: 1px solid #C0C9D6; border-radius: 5px;"
            "}"
            "QFrame#CfVersionCard:hover {"
            " background-color: #ECEFF4; border-color: #A8B4C4;"
            "}"
        )
        layout = QVBoxLayout(card)
        layout.setContentsMargins(8, 7, 8, 7)
        layout.setSpacing(3)

        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(4)

        tag_lbl = QLabel(tag, card)
        if danger:
            tag_lbl.setStyleSheet(
                "QLabel { background-color: #FAEEEF; color: #BF616A;"
                " border: 1px solid #E5C0C5; border-radius: 3px;"
                ' font-family: "IBM Plex Mono"; font-size: 9px;'
                " font-weight: 600; letter-spacing: 0.06em; padding: 1px 5px; }"
            )
        else:
            tag_lbl.setStyleSheet(
                "QLabel { background-color: #F1F4F8; color: #4C566A;"
                " border: 1px solid #D0D6E0; border-radius: 3px;"
                ' font-family: "IBM Plex Mono"; font-size: 9px;'
                " font-weight: 600; letter-spacing: 0.06em; padding: 1px 5px; }"
            )
        top.addWidget(tag_lbl)
        top.addStretch(1)

        arrow = QLabel("↗", card)
        arrow.setStyleSheet("color: #88909F; font-size: 10px;")
        top.addWidget(arrow, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(top)

        ts_lbl = QLabel(timestamp_text, card)
        ts_lbl.setStyleSheet(
            'font-family: "IBM Plex Mono"; font-size: 9px; color: #88909F;'
        )
        layout.addWidget(ts_lbl)
        return card

    def _build_properties(self, conflict: SyncConflictInfo) -> QWidget:
        container = QWidget(self._content)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        eyebrow = QLabel("PROPERTIES", container)
        eyebrow.setStyleSheet(_EYEBROW_CSS)
        layout.addWidget(eyebrow)

        device_alias = (
            (self._device_alias_resolver(conflict.origin_device_id)
             if self._device_alias_resolver else None)
            or conflict.origin_device_id
            or "unknown"
        )

        rows: list[tuple[str, str | None, QWidget | None]] = [
            ("Path", conflict.archived_virtual_path or "-", None),
            ("Reason", conflict.reason_code, None),
            ("Device", None, self._build_device_widget(device_alias, conflict.origin_device_id, container)),
            ("Created", format_datetime(conflict.created_at), None),
            ("Status", None, self._build_status_badge(conflict.status, container)),
        ]

        grid = QFrame(container)
        grid.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        grid.setStyleSheet(
            "QFrame { background-color: #F8FAFC; border: 1px solid #E8ECF4;"
            " border-radius: 4px; }"
        )
        grid_layout = QVBoxLayout(grid)
        grid_layout.setContentsMargins(0, 0, 0, 0)
        grid_layout.setSpacing(0)

        for i, (key, value, widget) in enumerate(rows):
            row_frame = QFrame(grid)
            row_frame.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
            row_frame.setStyleSheet("QFrame { background: transparent; border: none; }")
            row_layout = QHBoxLayout(row_frame)
            row_layout.setContentsMargins(10, 6, 10, 6)
            row_layout.setSpacing(12)

            key_lbl = QLabel(key, row_frame)
            key_lbl.setStyleSheet(_KEY_CSS)
            key_lbl.setFixedWidth(72)
            row_layout.addWidget(key_lbl, 0, Qt.AlignmentFlag.AlignTop)

            if widget is not None:
                row_layout.addWidget(widget, 1)
            else:
                val_lbl = QLabel(str(value or "-"), row_frame)
                val_lbl.setStyleSheet(_VALUE_CSS)
                val_lbl.setWordWrap(True)
                val_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                row_layout.addWidget(val_lbl, 1)

            grid_layout.addWidget(row_frame)

            if i < len(rows) - 1:
                sep = QFrame(grid)
                sep.setFixedHeight(1)
                sep.setStyleSheet("QFrame { background-color: #E8ECF4; border: none; }")
                grid_layout.addWidget(sep)

        layout.addWidget(grid)
        return container

    def _build_device_widget(
        self, alias: str, device_id: str | None, parent: QWidget
    ) -> QWidget:
        from app.ui.gui.setup.icons import tinted_icon

        w = QWidget(parent)
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(5)

        icon_lbl = QLabel(w)
        icon_lbl.setPixmap(
            tinted_icon("desktop", size=11, color=TOKENS.colors.text_secondary).pixmap(11, 11)
        )
        icon_lbl.setFixedSize(13, 13)
        lay.addWidget(icon_lbl, 0, Qt.AlignmentFlag.AlignVCenter)

        name_lbl = QLabel(alias, w)
        name_lbl.setStyleSheet(
            'font-family: "IBM Plex Sans"; font-size: 12px;'
            " font-weight: 600; color: #2E3440;"
        )
        lay.addWidget(name_lbl)

        if device_id and device_id != alias:
            id_lbl = QLabel(device_id, w)
            id_lbl.setStyleSheet(
                'font-family: "IBM Plex Mono"; font-size: 10px; color: #88909F;'
            )
            lay.addWidget(id_lbl)

        lay.addStretch(1)
        return w

    def _build_status_badge(self, status: str, parent: QWidget) -> QLabel:
        is_active = status == "active"
        is_restored = status == "resolved"
        if is_active:
            bg, fg, border = "#FAEEEF", "#BF616A", "#E5C0C5"
        elif is_restored:
            bg, fg, border = "#EEF5F0", "#2D6A4F", "#C3E6CB"
        else:
            bg, fg, border = "#F1F4F8", "#4C566A", "#D0D6E0"
        badge = QLabel(status.upper(), parent)
        badge.setStyleSheet(
            f"QLabel {{ background-color: {bg}; color: {fg};"
            f" border: 1px solid {border}; border-radius: 9px;"
            ' font-family: "IBM Plex Mono"; font-size: 10px;'
            " font-weight: 600; padding: 2px 8px; }"
        )
        return badge

    def _build_actions(self, conflict: SyncConflictInfo, is_active: bool) -> QWidget:
        container = QWidget(self._content)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)

        eyebrow = QLabel("ACTIONS", container)
        eyebrow.setStyleSheet(_EYEBROW_CSS)
        layout.addWidget(eyebrow)

        self.restore_button = _ActionRow(
            "arrow-counter-clockwise",
            "Restore from archive",
            "unarchive to a destination folder",
            variant="primary",
            parent=container,
        )
        self.delete_button = _ActionRow(
            "trash",
            "Delete archived item",
            "requires typing DELETE",
            variant="danger",
            parent=container,
        )
        trigger_type = conflict.trigger_event_type or "event"
        self.alias_button = _ActionRow(
            "user-circle",
            "Set device alias",
            f"labels {conflict.origin_device_id or 'device'} in future listings",
            parent=container,
        )
        self.inspect_button = _ActionRow(
            "code",
            "Inspect trigger event",
            f"view raw {trigger_type} payload",
            parent=container,
        )

        for btn in (self.restore_button, self.delete_button, self.alias_button, self.inspect_button):
            layout.addWidget(btn)
            if not is_active and btn is not self.inspect_button:
                btn.setEnabled(False)

        return container

    def _build_divider(self) -> QWidget:
        line = QFrame(self._content)
        line.setFixedHeight(1)
        line.setStyleSheet("background-color: #E8ECF4;")
        return line


__all__ = ["DetailPane"]
