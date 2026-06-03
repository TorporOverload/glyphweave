"""Password / generic field inputs, list/tree/table chrome, and sidebar /
top-bar object-name styling."""

from __future__ import annotations

from .helpers import StyleCtx, c


def build(ctx: StyleCtx) -> str:
    colors = ctx.colors
    radius = ctx.radius
    spacing = ctx.spacing
    sizes = ctx.sizes
    field = ctx.field
    tokens = ctx.tokens

    return f"""
/* ------ Password field ------ */

QLineEdit[role="password"] {{
    min-height: 40px;
    padding: 0 13px;
    background-color: {c(colors.bg_base)};
    color: {c(colors.text_primary)};
    border: 1px solid {c(colors.border_default)};
    border-radius: {radius.sm}px;
}}

QLineEdit[role="password"]:hover {{
    border: 1px solid {c(field.hover.border)};
}}

QLineEdit[role="password"]:focus {{
    border: 1px solid {c(colors.focus_ring)};
}}

QLineEdit[role="password"][state="error"] {{
    border: 1px solid {c(colors.border_error)};
}}

/* ------ Generic fields ------ */

QLineEdit,
QPlainTextEdit,
QTextEdit,
QComboBox {{
    min-height: {sizes.control_default}px;
    padding: 0 {spacing.md}px;
    background-color: {c(field.default.bg)};
    color: {c(colors.text_primary)};
    border: 1px solid {c(field.default.border)};
    border-radius: {radius.sm}px;
    selection-background-color: {c(colors.action_primary_fill)};
    selection-color: {c(colors.action_primary_text)};
}}

QPlainTextEdit,
QTextEdit {{
    padding-top: {spacing.sm}px;
    padding-bottom: {spacing.sm}px;
}}

QLineEdit:hover,
QPlainTextEdit:hover,
QTextEdit:hover,
QComboBox:hover {{
    border: 1px solid {c(field.hover.border)};
}}

QLineEdit:focus,
QPlainTextEdit:focus,
QTextEdit:focus,
QComboBox:focus {{
    border: 1px solid {c(colors.focus_ring)};
}}

QLineEdit[state="error"],
QPlainTextEdit[state="error"],
QTextEdit[state="error"],
QComboBox[state="error"] {{
    border: 1px solid {c(colors.border_error)};
}}

/* ------ Lists / trees / tables ------ */

QListWidget,
QTreeWidget,
QTableWidget {{
    background-color: {c(colors.bg_elevated)};
    border: 1px solid {c(colors.border_soft)};
    border-radius: {radius.md}px;
    outline: none;
}}

QListWidget::item,
QTreeWidget::item,
QTableWidget::item {{
    padding: {spacing.sm}px;
}}

QListWidget::item:selected,
QTreeWidget::item:selected,
QTableWidget::item:selected {{
    background-color: {c(colors.bg_subtle)};
    color: {c(colors.text_primary)};
}}

QScrollArea,
QScrollArea > QWidget > QWidget {{
    background: transparent;
    border: none;
}}

/* ------ Sidebar / TopBar (object-name based) ------ */

QWidget#SidebarNav {{
    background-color: {c(tokens.sidebar_nav.bg)};
    border-right: 1px solid {c(tokens.sidebar_nav.border)};
}}

QPushButton[role="sidebar-item"] {{
    min-height: 42px;
    padding: 0 {spacing.lg}px;
    border-radius: {radius.sm}px;
    text-align: left;
    background-color: {c(tokens.sidebar_nav.item_default.bg)};
    color: {c(tokens.sidebar_nav.item_default.fg)};
    border: 1px solid transparent;
}}

QPushButton[role="sidebar-item"]:hover {{
    background-color: {c(tokens.sidebar_nav.item_hover.bg)};
    color: {c(tokens.sidebar_nav.item_hover.fg)};
    border: 1px solid {c(tokens.sidebar_nav.item_hover.border)};
}}

QPushButton[role="sidebar-item"][state="active"] {{
    background-color: {c(tokens.sidebar_nav.item_active.bg)};
    color: {c(tokens.sidebar_nav.item_active.fg)};
    border: 1px solid {c(tokens.sidebar_nav.item_active.border)};
}}

QWidget#TopBar {{
    background-color: {c(tokens.top_bar.bg)};
    border-bottom: 1px solid {c(tokens.top_bar.border)};
}}
"""
