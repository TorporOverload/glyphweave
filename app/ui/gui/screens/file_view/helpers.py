"""Utility helpers shared by the file-view package: a colour-to-CSS string
helper, a tinted Phosphor-icon loader, and the small ``ElidedLabel`` /
``IconLabel`` widgets used inside the inspector and file rows."""

from __future__ import annotations

import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QIcon, QResizeEvent
from PySide6.QtWidgets import QLabel, QSizePolicy, QWidget

from app.ui.gui.setup import TOKENS
from app.ui.gui.setup.icons import tinted_icon as _shared_tinted_icon


_WRAP_BREAKS = re.compile(r"([_./\\\-])")
_LONG_RUN = re.compile(r"[A-Za-z0-9]{12,}")
_SOFT_HYPHEN_EVERY = 10


def _inject_soft_hyphens(match: "re.Match[str]") -> str:
    word = match.group(0)
    n = _SOFT_HYPHEN_EVERY
    return "­".join(word[i : i + n] for i in range(0, len(word), n))


def force_wrap(text: str) -> str:
    """Inject break opportunities so a word-wrapping QLabel can break inside
    long unbroken filenames/paths.

    Two passes:
    - Zero-width spaces (U+200B) after separator chars (``_ . / \\ -``) so the
      label can wrap right after a visible separator.
    - Soft hyphens (U+00AD) inserted every ~10 chars inside any run of 12+
      alphanumerics - so even ``ReallyLongCamelCaseWithNoBreaks`` will wrap
      onto multiple lines, rendering a literal ``-`` at the break point.
    """
    if not text:
        return text
    text = _WRAP_BREAKS.sub("\\1​", text)
    text = _LONG_RUN.sub(_inject_soft_hyphens, text)
    return text


def tinted_icon(
    name: str, *, size: int = 18, color: QColor | None = None
) -> QIcon:
    """Cached tint helper - thin wrapper over
    :func:`app.ui.gui.setup.icons.tinted_icon` that defaults the colour to
    ``text_secondary`` so file-view callers don't have to.

    Routing through the central function ensures the file table benefits
    from the (name, size, color) cache instead of re-rendering the same
    SVG hundreds of times when listing a folder full of one filetype."""
    return _shared_tinted_icon(
        name, size=size, color=color or TOKENS.colors.text_secondary
    )


def css(color: QColor) -> str:
    """Render a QColor as a Qt stylesheet colour string."""
    if color.alpha() == 255:
        return color.name()
    a = color.alpha() / 255
    return f"rgba({color.red()}, {color.green()}, {color.blue()}, {a:.3f})"


class ElidedLabel(QLabel):
    """A QLabel that elides its text to the available width and surfaces the
    full string on hover via the tooltip."""

    def __init__(
        self,
        text: str = "",
        mode: Qt.TextElideMode = Qt.TextElideMode.ElideRight,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(text, parent)
        self._mode = mode
        self._full_text = text
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

    def setText(self, text: str) -> None:  # type: ignore[override]
        self._full_text = text
        self.setToolTip(text)
        super().setText(text)
        self._sync_text()

    def full_text(self) -> str:
        return self._full_text

    def resizeEvent(self, event: QResizeEvent) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._sync_text()

    def _sync_text(self) -> None:
        metrics = self.fontMetrics()
        elided = metrics.elidedText(self._full_text, self._mode, self.width())
        super().setText(elided)


class IconLabel(QLabel):
    """Fixed-size QLabel that displays a tinted Phosphor icon."""

    def __init__(
        self,
        icon_name: str,
        *,
        size: int = 16,
        color: QColor | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.setPixmap(
            tinted_icon(icon_name, size=size, color=color).pixmap(size, size)
        )
