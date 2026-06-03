"""Custom ``QStyledItemDelegate`` subclasses for the file-view list.

Each delegate is responsible for painting a single column entirely in
``QPainter`` rather than embedding per-row widgets, which keeps the list
fast at large row counts.

``FileNameDelegate`` (column 0)
    Renders a tinted icon followed by the filename, eliding overflow text
    with an ellipsis.

``TypeBadgeDelegate`` (column 1)
    Renders a rounded-rectangle pill badge containing the file-type label,
    drawn in a translucent tint of the accent colour supplied in the payload.

Both delegates read their per-row data from the ``ROW_PAYLOAD_ROLE`` custom
``Qt.ItemDataRole`` that the view model stores on each index, rather than the
standard ``DisplayRole`` / ``DecorationRole``, so arbitrary metadata can be
packed into a single dict without extra model columns.
"""
from __future__ import annotations

from typing import Any

from PySide6.QtCore import QRect, QSize, Qt
from PySide6.QtGui import QBrush, QColor, QFont, QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import QStyledItemDelegate, QStyleOptionViewItem

from app.ui.gui.setup import TOKENS
from app.ui.gui.setup.icons import tinted_icon


# Custom data role for the per-row payload dict. Above Qt's reserved
# range so it can't collide with built-ins like UserRole + 0/1.
ROW_PAYLOAD_ROLE = Qt.ItemDataRole.UserRole + 10

_NAME_FONT_PX = 12
_BADGE_FONT_PX = 10
_BADGE_HEIGHT = 18
_BADGE_HPAD = 8
_ICON_SIZE = 14
_LEFT_PAD = 12
_ICON_TEXT_GAP = 8


def _payload(index) -> dict | None:
    data = index.data(ROW_PAYLOAD_ROLE)
    return data if isinstance(data, dict) else None


class FileNameDelegate(QStyledItemDelegate):
    """Paints column 0 (icon + filename) without per-row widgets."""

    def paint(
        self,
        painter: QPainter,
        option: QStyleOptionViewItem,
        index,
    ) -> None:
        # Let the base class draw the row's selection / hover background;
        # we only override the cell content.
        super().paint(painter, option, index)

        payload = _payload(index)
        if payload is None:
            return

        icon_name = payload.get("icon_name")
        icon_color: QColor = payload.get("icon_color") or TOKENS.colors.text_secondary
        name = payload.get("name", "")
        rect: QRect = option.rect

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        if icon_name:
            icon_y = rect.y() + (rect.height() - _ICON_SIZE) // 2
            icon_rect = QRect(rect.x() + _LEFT_PAD, icon_y, _ICON_SIZE, _ICON_SIZE)
            tinted_icon(icon_name, size=_ICON_SIZE, color=icon_color).paint(
                painter, icon_rect
            )
            text_x = icon_rect.right() + _ICON_TEXT_GAP
        else:
            text_x = rect.x() + _LEFT_PAD

        font = QFont("IBM Plex Sans")
        font.setPixelSize(_NAME_FONT_PX)
        painter.setFont(font)
        painter.setPen(QPen(TOKENS.colors.text_primary))
        text_rect = QRect(
            text_x,
            rect.y(),
            max(0, rect.right() - text_x - 8),
            rect.height(),
        )
        # Elide on overflow so long filenames never spill past the cell.
        elided = QFontMetrics(font).elidedText(
            name, Qt.TextElideMode.ElideRight, text_rect.width()
        )
        painter.drawText(
            text_rect,
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            elided,
        )
        painter.restore()

    def sizeHint(
        self,
        option: QStyleOptionViewItem,
        index,
    ) -> QSize:
        return QSize(0, 36)


class TypeBadgeDelegate(QStyledItemDelegate):
    """Paints column 1 (centered type-label pill) without per-row widgets."""

    def paint(
        self,
        painter: QPainter,
        option: QStyleOptionViewItem,
        index,
    ) -> None:
        super().paint(painter, option, index)
        payload = _payload(index)
        if payload is None:
            return
        label = payload.get("type_label")
        accent_value: Any = payload.get("type_accent") or "#5e81ac"
        if not label:
            return

        accent = QColor(accent_value) if not isinstance(accent_value, QColor) else accent_value
        bg = QColor(accent)
        bg.setAlpha(38)

        rect: QRect = option.rect
        font = QFont("IBM Plex Mono")
        font.setPixelSize(_BADGE_FONT_PX)
        font.setWeight(QFont.Weight.DemiBold)
        text_w = QFontMetrics(font).horizontalAdvance(label)
        badge_w = text_w + _BADGE_HPAD * 2
        badge_x = rect.x() + (rect.width() - badge_w) // 2
        badge_y = rect.y() + (rect.height() - _BADGE_HEIGHT) // 2
        badge_rect = QRect(badge_x, badge_y, badge_w, _BADGE_HEIGHT)

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(bg))
        painter.drawRoundedRect(badge_rect, 3, 3)
        painter.setFont(font)
        painter.setPen(QPen(accent))
        painter.drawText(
            badge_rect,
            Qt.AlignmentFlag.AlignCenter,
            label,
        )
        painter.restore()


__all__ = [
    "FileNameDelegate",
    "ROW_PAYLOAD_ROLE",
    "TypeBadgeDelegate",
]
