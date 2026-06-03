from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup import (
    TOKENS,
    ButtonVariant,
    Role,
    Tone,
    apply_button,
    apply_text_style,
    set_properties,
    set_tone,
)
from app.ui.gui.setup.tokens.colors import to_css_color as css_color

from .helpers import IconLabel

if TYPE_CHECKING:
    from .screen import SearchScreen


def build_header(screen: "SearchScreen") -> None:
    """The new overlay design does not use a title/status header.

    ``SearchScreen`` still calls this function because it is also used by the
    shell stack. Keep a tiny no-op compatibility section by only creating the
    attributes that the state machine expects.
    """
    screen._title_label = QLabel("", screen)
    screen._title_label.setVisible(False)
    screen._status_badge = _InlineStatus(screen)


def build_search_input(screen: "SearchScreen") -> None:
    screen._search_bar = QFrame(screen)
    screen._search_bar.setObjectName("SearchCommandBar")
    screen._search_bar.setFixedHeight(58)
    screen._search_bar.setStyleSheet(f"""
        QFrame#SearchCommandBar {{
            background-color: {css_color(TOKENS.colors.bg_panel)};
            border: none;
            border-top-left-radius: {TOKENS.radius.md}px;
            border-top-right-radius: {TOKENS.radius.md}px;
            border-bottom: 1px solid {css_color(TOKENS.colors.border_soft)};
        }}
        QLineEdit#SearchCommandInput {{
            background: transparent;
            border: none;
            padding: 0;
            min-height: 50px;
            color: {css_color(TOKENS.colors.text_primary)};
            font-family: "{TOKENS.typography.family_mono}";
            font-size: 14px;
        }}
        QLineEdit#SearchCommandInput:focus,
        QLineEdit#SearchCommandInput:hover {{
            border: none;
        }}
        QPushButton#SearchCloseButton {{
            min-width: 28px;
            max-width: 28px;
            min-height: 28px;
            max-height: 28px;
            padding: 0;
            background-color: transparent;
            border: 1px solid transparent;
            border-radius: 14px;
            color: {css_color(TOKENS.colors.text_secondary)};
            font-size: 17px;
            font-weight: 400;
        }}
        QPushButton#SearchCloseButton:hover {{
            background-color: {css_color(TOKENS.colors.bg_subtle)};
            border-color: {css_color(TOKENS.colors.border_soft)};
        }}
        QPushButton#SearchEscHint {{
            min-height: 22px;
            max-height: 22px;
            padding: 0 7px;
            background-color: {css_color(TOKENS.colors.bg_subtle)};
            border: 1px solid {css_color(TOKENS.colors.border_soft)};
            border-radius: 4px;
            color: {css_color(TOKENS.colors.text_muted)};
            font-family: "{TOKENS.typography.family_mono}";
            font-size: 10px;
            font-weight: 400;
        }}
        QPushButton#SearchEscHint:hover {{
            background-color: {css_color(TOKENS.colors.bg_elevated)};
        }}
    """)

    layout = QHBoxLayout(screen._search_bar)
    layout.setContentsMargins(18, 0, 18, 0)
    layout.setSpacing(12)

    screen._close_button = QPushButton("×", screen._search_bar)
    screen._close_button.setObjectName("SearchCloseButton")
    screen._close_button.setCursor(Qt.CursorShape.PointingHandCursor)
    screen._close_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    screen._close_button.clicked.connect(screen._on_close_clicked)
    layout.addWidget(screen._close_button)

    screen._search_icon = IconLabel(
        "magnifying-glass",
        size=16,
        color=QColor(TOKENS.colors.text_secondary),
        parent=screen._search_bar,
    )
    layout.addWidget(screen._search_icon)

    screen._search_input = QLineEdit(screen._search_bar)
    screen._search_input.setObjectName("SearchCommandInput")
    screen._search_input.setPlaceholderText("Search files and content...")
    screen._search_input.textChanged.connect(screen._on_query_changed)
    layout.addWidget(screen._search_input, 1)

    screen._clear_button = QPushButton("esc", screen._search_bar)
    screen._clear_button.setObjectName("SearchEscHint")
    screen._clear_button.setCursor(Qt.CursorShape.ArrowCursor)
    screen._clear_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    layout.addWidget(screen._clear_button)

    screen._root_layout.addWidget(screen._search_bar)


def build_filters(screen: "SearchScreen") -> None:
    filter_row = QWidget(screen)
    filter_row.setObjectName("SearchFilterRow")
    filter_row.setFixedHeight(50)
    filter_row.setStyleSheet(f"""
        QWidget#SearchFilterRow {{
            background-color: {css_color(TOKENS.colors.bg_panel)};
            border-bottom: 1px solid {css_color(TOKENS.colors.border_soft)};
        }}
        QLabel#searchScopeLabel,
        QLabel#SearchResultsCount {{
            color: {css_color(TOKENS.colors.text_muted)};
            font-family: "{TOKENS.typography.family_mono}";
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }}
        QPushButton#searchScopePill {{
            min-height: 24px;
            padding: 0 12px;
            border-radius: 12px;
            border: 1px solid {css_color(TOKENS.colors.border_soft)};
            background-color: {css_color(TOKENS.colors.bg_subtle)};
            color: {css_color(TOKENS.colors.text_secondary)};
            font-family: "{TOKENS.typography.family_mono}";
            font-size: 11px;
            font-weight: 500;
        }}
        QPushButton#searchScopePill[state="active"] {{
            background-color: {css_color(TOKENS.colors.action_primary_fill)};
            border-color: {css_color(TOKENS.colors.action_primary_fill)};
            color: {css_color(TOKENS.colors.action_primary_text)};
        }}
    """)

    filter_layout = QHBoxLayout(filter_row)
    filter_layout.setContentsMargins(18, 9, 18, 9)
    filter_layout.setSpacing(10)

    scope_label = QLabel("SCOPE", filter_row)
    scope_label.setObjectName("searchScopeLabel")
    filter_layout.addWidget(scope_label)

    for value, label in screen.SCOPES:
        pill = QPushButton(label, filter_row)
        pill.setCheckable(True)
        pill.setCursor(Qt.CursorShape.PointingHandCursor)
        pill.setObjectName("searchScopePill")
        apply_button(pill, ButtonVariant.GHOST, size="sm")
        pill.setProperty("scope", value)
        pill.clicked.connect(
            lambda _checked=False, v=value: screen._on_scope_clicked(v)
        )
        screen._scope_buttons[value] = pill
        filter_layout.addWidget(pill)

    screen._set_scope("all")
    filter_layout.addStretch(1)

    screen._results_count_label = QLabel("", filter_row)
    screen._results_count_label.setObjectName("SearchResultsCount")
    filter_layout.addWidget(screen._results_count_label)

    screen._root_layout.addWidget(filter_row)


def build_results_area(screen: "SearchScreen") -> None:
    screen._results_summary = QLabel("", screen)
    screen._results_summary.setVisible(False)

    screen._results_scroll = QScrollArea(screen)
    screen._results_scroll.setWidgetResizable(True)
    screen._results_scroll.setMinimumHeight(320)
    screen._results_scroll.setFrameShape(QFrame.Shape.NoFrame)
    screen._results_scroll.setHorizontalScrollBarPolicy(
        Qt.ScrollBarPolicy.ScrollBarAlwaysOff
    )
    screen._results_scroll.setStyleSheet(
        "QScrollArea { background: transparent; border: none; }"
    )

    screen._results_container = QWidget(screen._results_scroll)
    screen._results_container.setObjectName("SearchResultsContainer")
    screen._results_container.setStyleSheet(f"""
        QWidget#SearchResultsContainer {{
            background-color: {css_color(TOKENS.colors.bg_panel)};
        }}
    """)
    screen._results_layout = QVBoxLayout(screen._results_container)
    screen._results_layout.setContentsMargins(0, 0, 0, 0)
    screen._results_layout.setSpacing(0)

    # Footer "Show more" button - pinned just above the trailing stretch so
    # new cards inserted by ``_render_results`` always appear above it.
    screen._show_more_button = QPushButton(
        "Show more results", screen._results_container
    )
    screen._show_more_button.setObjectName("SearchShowMoreButton")
    screen._show_more_button.setCursor(Qt.CursorShape.PointingHandCursor)
    screen._show_more_button.setFlat(True)
    screen._show_more_button.setStyleSheet(f"""
        QPushButton#SearchShowMoreButton {{
            background: transparent;
            border: none;
            border-top: 1px solid {css_color(TOKENS.colors.border_soft)};
            padding: 12px 0;
            color: {css_color(TOKENS.colors.action_primary_fill)};
            font-family: "{TOKENS.typography.family_ui}";
            font-size: 12px;
            font-weight: 600;
        }}
        QPushButton#SearchShowMoreButton:hover {{
            background-color: {css_color(TOKENS.colors.bg_subtle)};
        }}
        QPushButton#SearchShowMoreButton:disabled {{
            color: {css_color(TOKENS.colors.text_muted)};
        }}
    """)
    screen._show_more_button.setVisible(False)
    screen._show_more_button.clicked.connect(screen._on_show_more_clicked)
    screen._results_layout.addWidget(screen._show_more_button)
    screen._results_layout.addStretch(1)

    screen._results_scroll.setWidget(screen._results_container)
    screen._root_layout.addWidget(screen._results_scroll, 1)

    screen._empty_state = QWidget(screen)
    screen._empty_state.setMinimumHeight(320)
    screen._empty_state.setObjectName("SearchEmptyState")
    screen._empty_state.setStyleSheet(f"""
        QWidget#SearchEmptyState {{
            background-color: {css_color(TOKENS.colors.bg_panel)};
        }}
    """)
    screen._empty_state.setVisible(False)
    empty_layout = QVBoxLayout(screen._empty_state)
    empty_layout.setContentsMargins(24, 28, 24, 28)
    empty_layout.setSpacing(TOKENS.spacing.sm)

    screen._empty_title = QLabel("No results", screen._empty_state)
    apply_text_style(screen._empty_title, TOKENS.typography.body)
    screen._empty_title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
    empty_layout.addWidget(screen._empty_title)

    screen._empty_hint = QLabel("Try a different search term", screen._empty_state)
    apply_text_style(screen._empty_hint, TOKENS.typography.caption)
    set_tone(screen._empty_hint, Tone.MUTED)
    screen._empty_hint.setAlignment(Qt.AlignmentFlag.AlignHCenter)
    empty_layout.addWidget(screen._empty_hint)

    screen._root_layout.addWidget(screen._empty_state, 1)

    screen._loading_label = QLabel("Searching...", screen)
    screen._loading_label.setMinimumHeight(320)
    screen._loading_label.setObjectName("SearchLoadingLabel")
    screen._loading_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
    screen._loading_label.setContentsMargins(24, 28, 24, 28)
    apply_text_style(screen._loading_label, TOKENS.typography.body)
    set_tone(screen._loading_label, Tone.MUTED)
    screen._loading_label.setStyleSheet(
        f"background-color: {css_color(TOKENS.colors.bg_panel)};"
    )
    screen._loading_label.setVisible(False)
    screen._root_layout.addWidget(screen._loading_label, 1)

    # Start collapsed - the overlay will resize to compact height until the
    # user types something that produces results.
    screen._results_scroll.setVisible(False)
    screen._loading_label.setVisible(False)
    screen._empty_state.setVisible(False)


def build_pagination(screen: "SearchScreen") -> None:
    """Pagination remains wired for keyboard/state compatibility, but the
    command-palette search design does not show footer controls."""
    pagination = QWidget(screen)
    pagination.setVisible(False)
    pagination_layout = QHBoxLayout(pagination)
    pagination_layout.setContentsMargins(0, 0, 0, 0)

    screen._prev_button = QPushButton("Prev", pagination)
    screen._prev_button.clicked.connect(screen._on_prev_page)
    pagination_layout.addWidget(screen._prev_button)

    screen._page_label = QLabel("Page 1", pagination)
    pagination_layout.addWidget(screen._page_label)

    screen._next_button = QPushButton("Next", pagination)
    screen._next_button.clicked.connect(screen._on_next_page)
    pagination_layout.addWidget(screen._next_button)

    screen._root_layout.addWidget(pagination)


def _separator(screen: "SearchScreen") -> QFrame:
    sep = QFrame(screen)
    sep.setFrameShape(QFrame.Shape.HLine)
    set_properties(sep, role=Role.SEPARATOR)
    return sep


class _InlineStatus:
    """Tiny compatibility shim for the old status badge API."""

    def __init__(self, _parent: QWidget | None = None) -> None:
        self.text = "Ready"

    def set_text(self, text: str) -> None:
        self.text = text
