"""Helpers shared by :mod:`search_screen` - icon utilities, the small status
badge in the page header, and the background search worker thread."""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QHBoxLayout, QLabel, QWidget

from app.services.models import SearchPage
from app.services.vault_service import VaultService
from app.ui.gui.setup import TOKENS, apply_text_style, ph_icon_path


_FILE_ICON_SPEC: dict[str, tuple[str, str]] = {
    ".pdf": ("file-pdf", "#bf616a"),
    ".xls": ("file-xls", "#2e9961"),
    ".xlsx": ("file-xls", "#2e9961"),
    ".csv": ("file-xls", "#2e9961"),
    ".png": ("file-image", "#7d5c87"),
    ".jpg": ("file-image", "#7d5c87"),
    ".jpeg": ("file-image", "#7d5c87"),
    ".gif": ("file-image", "#7d5c87"),
    ".md": ("file-code", "#4c566a"),
    ".json": ("file-code", "#5e81ac"),
    ".qmd": ("file-code", "#5e81ac"),
    ".py": ("file-code", "#5e81ac"),
    ".zip": ("file-archive", "#434c5e"),
    ".wav": ("file-audio", "#d08770"),
    ".mp3": ("file-audio", "#d08770"),
}


def file_icon_spec(name: str) -> tuple[str, str]:
    suffix = Path(name).suffix.lower()
    return _FILE_ICON_SPEC.get(suffix, ("file-text", "#5e81ac"))


def tinted_icon(
    name: str,
    *,
    size: int = 18,
    color: QColor | None = None,
) -> QIcon:
    """Look up the SVG by file name directly so a typo doesn't silently
    drop the icon."""
    if not name.endswith(".svg"):
        name = f"{name}.svg"
    renderer = QSvgRenderer(str(ph_icon_path(name)))
    if not renderer.isValid():
        return QIcon()

    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)
    painter = QPainter(px)
    renderer.render(painter)
    painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
    painter.fillRect(px.rect(), color or QColor("#5e81ac"))
    painter.end()
    return QIcon(px)


class IconLabel(QLabel):
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


class StatusBadgeLight(QWidget):
    """Small dot-and-text pill shown in the search-screen header (Ready /
    Searching… / Error)."""

    def __init__(
        self,
        text: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._text = text
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(4)

        self._label = QLabel(self._text, self)
        apply_text_style(self._label, TOKENS.typography.badge)
        layout.addWidget(self._label)

        self.setStyleSheet(
            "StatusBadgeLight { background-color: #3b4252; border-radius: 4px; }"
        )

    def set_text(self, text: str) -> None:
        self._label.setText(text)


class SearchWorker(QThread):
    """Runs a single :meth:`VaultService.search_page` call off the GUI thread.

    Cooperatively cancellable via :meth:`cancel` - the screen calls this
    before issuing a new search so we don't render stale results."""

    results_ready = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        service: VaultService,
        query: str,
        page: int = 0,
        limit: int = 20,
        scope: str = "all",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._query = query
        self._page = page
        self._limit = limit
        self._scope = scope
        self._cancel_event = threading.Event()

    def cancel(self) -> None:
        self._cancel_event.set()

    def run(self) -> None:
        if self._cancel_event.is_set():
            return

        try:
            offset = self._page * self._limit
            result: SearchPage = self._service.search_page(
                self._query,
                limit=self._limit,
                offset=offset,
                scope=self._scope,
            )

            if self._cancel_event.is_set():
                return

            self.results_ready.emit(result)

        except Exception as exc:
            if not self._cancel_event.is_set():
                self.failed.emit(str(exc))
