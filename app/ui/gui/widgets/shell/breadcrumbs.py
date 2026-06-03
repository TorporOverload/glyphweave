"""Slim breadcrumbs row shown below the TopBar in file view.

Layout: ``[crumbs ...]   [Sync now]``

The crumbs area never drives the window wider than its parent - when the
full path would overflow the available width, left-hand segments are
collapsed into a single ``...`` label so the deepest (current) segment
is always visible.
"""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QFont, QFontMetrics
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QWidget,
)

from app.ui.gui.setup import TOKENS

from .helpers import css_color

# Pixel size used for the crumb labels. must match the QSS value so that
# the font-metrics measurement matches the rendered label widths.
_CRUMB_FONT_PX = 13


def _crumb_fm() -> QFontMetrics:
    font = QFont("IBM Plex Sans")
    font.setPixelSize(_CRUMB_FONT_PX)
    return QFontMetrics(font)


class _BreadcrumbsBar(QWidget):
    sync_now_clicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setObjectName("BreadcrumbsBar")
        self.setFixedHeight(31)
        outer = QHBoxLayout(self)
        outer.setContentsMargins(20, 0, 20, 0)
        outer.setSpacing(8)

        # Crumbs container - stretch factor 1 so it absorbs all available
        # horizontal space; minimum width 0 so it never drives the window
        # wider than the content area.
        self._crumbs_host = QWidget(self)
        self._crumbs_host.setStyleSheet("background: transparent;")
        self._crumbs_host.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self._crumbs_host.setMinimumWidth(0)
        self._crumb_layout = QHBoxLayout(self._crumbs_host)
        self._crumb_layout.setContentsMargins(0, 0, 0, 0)
        self._crumb_layout.setSpacing(6)
        outer.addWidget(self._crumbs_host, 1, Qt.AlignmentFlag.AlignVCenter)

        # Sync now button on the right.
        from app.ui.gui.setup.icons import tinted_icon

        self._sync_button = QPushButton("Sync now", self)
        self._sync_button.setObjectName("BreadcrumbsSyncBtn")
        self._sync_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._sync_button.setFlat(True)
        self._sync_button.setFixedHeight(22)
        self._sync_button.setIcon(
            tinted_icon(
                "arrows-clockwise",
                size=11,
                color=TOKENS.colors.text_secondary,
            )
        )
        self._sync_button.setIconSize(QSize(11, 11))
        self._sync_button.setStyleSheet(f"""
            QPushButton#BreadcrumbsSyncBtn {{
                background-color: transparent;
                border: 1px solid transparent;
                border-radius: 4px;
                padding: 0 9px;
                font-family: "IBM Plex Sans";
                font-size: 10px;
                color: {css_color(TOKENS.colors.text_secondary)};
            }}
            QPushButton#BreadcrumbsSyncBtn:hover {{
                background-color: {css_color(TOKENS.colors.bg_elevated)};
                border-color: {css_color(TOKENS.colors.border_soft)};
            }}
        """)
        self._sync_button.clicked.connect(self.sync_now_clicked.emit)
        outer.addWidget(self._sync_button, 0, Qt.AlignmentFlag.AlignVCenter)

        self._all_parts: list[str] = []
        self._crumbs: list[QLabel] = []
        self.set_crumbs(["glyphweave"])

    # Public API

    def set_crumbs(self, parts: list[str]) -> None:
        self._all_parts = list(parts)
        self._rebuild_crumbs()

    # Qt overrides

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._rebuild_crumbs()

    # internal helpers

    def _available_crumb_width(self) -> int:
        """Pixel budget for the crumb labels inside _crumbs_host."""
        # outer margins: 20 left + 20 right = 40
        # sync button: actual hint width + 8px gap before it
        sync_w = self._sync_button.sizeHint().width() + 8
        return max(40, self.width() - 40 - sync_w)

    def _fit_parts(self, parts: list[str]) -> list[str]:
        """Return the visible subset of *parts*, inserting '...' if needed.

        Strategy: always keep the leftmost part (vault/root name) and the
        rightmost part (current location).  Drop segments from the left
        side of the remaining middle sections until everything fits, then
        prepend '...' to signal the hidden ancestry.
        """
        if len(parts) <= 1:
            return list(parts)

        available = self._available_crumb_width()
        fm = _crumb_fm()
        # Each separator "/" label + 2 × layout spacing (6 px each side).
        sep_w = fm.horizontalAdvance("/") + 12

        def total_w(p: list[str]) -> int:
            return (
                sum(fm.horizontalAdvance(s) for s in p)
                + sep_w * (len(p) - 1)
            )

        if total_w(parts) <= available:
            return list(parts)

        first = parts[0]
        ellipsis = "..."

        # Try first + "..." + progressively fewer tail segments.
        for n in range(len(parts) - 1, 0, -1):
            tail = parts[-n:]
            candidate = [first, ellipsis] + tail
            if total_w(candidate) <= available:
                return candidate

        # Absolute minimum: vault name + "..." + current segment only.
        return [first, ellipsis, parts[-1]]

    def _rebuild_crumbs(self) -> None:
        parts = self._all_parts if self._all_parts else ["glyphweave"]
        self._render_crumbs(self._fit_parts(parts))

    def _render_crumbs(self, parts: list[str]) -> None:
        """Tear down existing crumb widgets and build fresh ones for *parts*."""
        # hide() before deleteLater() so the widget doesn't briefly appear as
        # a top-level window - setParent(None) on a visible child promotes it.
        while self._crumb_layout.count():
            item = self._crumb_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.hide()
                widget.deleteLater()
        self._crumbs = []

        # Parent crumbs sit slightly muted; the current location is dark+bold.
        # "..." uses the same muted style as parent crumbs.
        # Separators are most muted so they don't pull the eye.
        parent_css = (
            'font-family: "IBM Plex Sans"; font-size: 13px;'
            f" color: {css_color(TOKENS.colors.text_secondary)};"
        )
        current_css = (
            'font-family: "IBM Plex Sans"; font-size: 13px; font-weight: 600;'
            f" color: {css_color(TOKENS.colors.text_primary)};"
        )
        sep_css = (
            'font-family: "IBM Plex Sans"; font-size: 13px;'
            f" color: {css_color(TOKENS.colors.text_muted)};"
        )

        for i, part in enumerate(parts):
            if i > 0:
                sep = QLabel("/", self._crumbs_host)
                sep.setStyleSheet(sep_css)
                self._crumb_layout.addWidget(sep)
                self._crumbs.append(sep)

            is_last = i == len(parts) - 1
            crumb = QLabel(part, self._crumbs_host)
            crumb.setStyleSheet(current_css if is_last else parent_css)
            self._crumb_layout.addWidget(crumb)
            self._crumbs.append(crumb)

        self._crumb_layout.addStretch(1)
