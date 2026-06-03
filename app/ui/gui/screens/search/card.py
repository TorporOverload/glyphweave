"""Compact result-row widget for the command-palette search overlay."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMenu,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.services.models import SearchResult
from app.ui.gui.setup import TOKENS, Tone, apply_text_style, set_tone
from app.ui.gui.setup.tokens.colors import to_css_color as css_color

from .helpers import IconLabel, file_icon_spec


class SearchResultCard(QFrame):
    clicked = Signal(int)
    open_requested = Signal(int)
    open_containing_folder_requested = Signal(str)
    copy_path_requested = Signal(str)

    def __init__(
        self,
        result: SearchResult,
        parent: QWidget | None = None,
        *,
        query: str = "",
    ) -> None:
        super().__init__(parent)
        self._result = result
        self._query = query
        self._selected = False
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setObjectName("SearchResultRow")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(90)
        self._build_ui()
        self._apply_row_style()

    def _build_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 10, 18, 10)
        layout.setSpacing(10)

        icon_name, accent_color = file_icon_spec(self._result.file_name)
        self._icon_label = IconLabel(
            icon_name,
            size=16,
            color=QColor(accent_color),
            parent=self,
        )
        layout.addWidget(self._icon_label, 0, Qt.AlignmentFlag.AlignTop)

        content = QVBoxLayout()
        content.setContentsMargins(0, 0, 0, 0)
        content.setSpacing(5)

        top_line = QHBoxLayout()
        top_line.setContentsMargins(0, 0, 0, 0)
        top_line.setSpacing(8)

        self._name_label = QLabel(self)
        self._name_label.setTextFormat(Qt.TextFormat.RichText)
        self._name_label.setText(
            self._highlight(self._trim_middle(self._result.file_name, 88))
        )
        self._name_label.setWordWrap(False)
        apply_text_style(self._name_label, TOKENS.typography.card_title)
        top_line.addWidget(self._name_label, 1)

        folder_path = self._folder_path_label()
        self._path_label = QLabel(folder_path, self)
        apply_text_style(self._path_label, TOKENS.typography.caption)
        set_tone(self._path_label, Tone.MUTED)
        self._path_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        top_line.addWidget(self._path_label, 0)
        content.addLayout(top_line)

        self._snippet_label = QLabel(self)
        self._snippet_label.setTextFormat(Qt.TextFormat.RichText)
        self._snippet_label.setText(
            self._highlight(self._trim_end(self._result.snippet, 120))
        )
        apply_text_style(self._snippet_label, TOKENS.typography.body)
        self._snippet_label.setWordWrap(False)
        self._snippet_label.setMaximumHeight(24)
        content.addWidget(self._snippet_label)

        meta_text = self._meta_text()
        self._meta_label = QLabel(meta_text, self)
        apply_text_style(self._meta_label, TOKENS.typography.caption)
        set_tone(self._meta_label, Tone.MUTED)
        content.addWidget(self._meta_label)

        layout.addLayout(content, 1)

    def _apply_row_style(self) -> None:
        bg = css_color(TOKENS.colors.bg_panel)
        hover = css_color(TOKENS.colors.bg_subtle)
        selected = css_color(TOKENS.colors.status_info_bg)
        border = css_color(TOKENS.colors.border_soft)
        self.setStyleSheet(f"""
            QFrame#SearchResultRow {{
                background-color: {bg};
                border: none;
                border-bottom: 1px solid {border};
                border-radius: 0;
            }}
            QFrame#SearchResultRow:hover {{
                background-color: {hover};
            }}
            QFrame#SearchResultRow[state="selected"] {{
                background-color: {selected};
            }}
        """)

    def _trim_middle(self, text: str, max_chars: int) -> str:
        if len(text) <= max_chars:
            return text
        keep = max_chars - 1
        left = keep // 2
        right = keep - left
        return f"{text[:left]}…{text[-right:]}"

    def _trim_end(self, text: str, max_chars: int) -> str:
        if len(text) <= max_chars:
            return text
        return f"{text[: max_chars - 1]}…"

    def _highlight(self, text: str) -> str:
        """HTML-escape ``text`` and highlight case-insensitive query terms."""
        import html
        import re

        escaped = html.escape(text)
        terms = [t for t in (self._query or "").strip().split() if t]
        if not terms:
            return escaped
        pattern = "|".join(re.escape(html.escape(t)) for t in terms)
        warm = TOKENS.colors.status_warning_bg.name()
        ink = TOKENS.colors.text_primary.name()
        return re.sub(
            f"({pattern})",
            lambda m: (
                f'<span style="background-color:{warm}; color:{ink};">'
                f"{m.group(0)}</span>"
            ),
            escaped,
            flags=re.IGNORECASE,
        )

    def _folder_virtual_path(self) -> str:
        folder = str(Path(self._result.virtual_path).parent).replace("\\", "/")
        return "/" if folder in {".", ""} else folder

    def _folder_path_label(self) -> str:
        folder = self._folder_virtual_path()
        if not folder.endswith("/"):
            folder = f"{folder}/"
        return folder

    def _meta_text(self) -> str:
        match_target = "filename" if self._matches_filename() else "content"
        score = max(0, min(99, round(float(self._result.rank or 0) * 100)))
        if score <= 0:
            return match_target
        return f"match {score}% · {match_target}"

    def _matches_filename(self) -> bool:
        name = self._result.file_name.lower()
        terms = [t.lower() for t in (self._query or "").strip().split() if t]
        return bool(terms) and any(term in name for term in terms)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._result.file_ref_id)
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.open_requested.emit(self._result.file_ref_id)
        super().mouseDoubleClickEvent(event)

    def contextMenuEvent(self, event) -> None:
        menu = QMenu(self)

        open_action = menu.addAction("Open")
        open_action.triggered.connect(
            lambda: self.open_requested.emit(self._result.file_ref_id)
        )

        folder_action = menu.addAction("Open containing folder")
        folder_action.triggered.connect(
            lambda: self.open_containing_folder_requested.emit(
                self._folder_virtual_path()
            )
        )

        copy_action = menu.addAction("Copy path")
        copy_action.triggered.connect(
            lambda: self.copy_path_requested.emit(self._result.virtual_path)
        )

        menu.exec(event.globalPos())

    def set_selected(self, selected: bool) -> None:
        self._selected = selected
        self.setProperty("state", "selected" if selected else "")
        self.style().unpolish(self)
        self.style().polish(self)
