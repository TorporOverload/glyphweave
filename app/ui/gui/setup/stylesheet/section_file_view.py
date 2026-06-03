"""File-view-specific styles: header + breadcrumbs + toolbar + tree + table
+ tabs + unlocked card + props/preview + footer."""

from __future__ import annotations

from .helpers import StyleCtx, c


def build(ctx: StyleCtx) -> str:
    colors = ctx.colors
    radius = ctx.radius
    spacing = ctx.spacing

    return f"""
/* ------ File view ------ */

QWidget[role="file-view"] {{
    background-color: {c(ctx.tokens.palette.nord6)};
}}

QFrame[role="file-header"] {{
    background-color: {c(colors.bg_panel)};
    border-bottom: 1px solid {c(colors.border_default)};
}}

QFrame[role="search-shell"] {{
    background-color: {c(colors.bg_elevated)};
    border: 1px solid {c(colors.border_default)};
    border-radius: {radius.md}px;
}}

QLineEdit[role="search"] {{
    min-height: 38px;
    border: none;
    background: transparent;
    padding: 0;
}}

QLineEdit[role="search"]:hover,
QLineEdit[role="search"]:focus {{
    border: none;
}}

QFrame[role="breadcrumbs"] {{
    background-color: {c(colors.bg_elevated)};
    border: 1px solid {c(colors.border_selected)};
    border-radius: {radius.sm}px;
}}

QFrame[role="file-toolbar"] {{
    background-color: {c(colors.bg_panel)};
    border-bottom: 1px solid {c(colors.border_soft)};
}}

QTableWidget[role="file-table"] {{
    border: none;
    border-radius: 0;
    background-color: {c(ctx.tokens.palette.nord6)};
    selection-background-color: #d6d7ec;
    selection-color: {c(colors.text_primary)};
}}

QTableWidget[role="file-table"]::item {{
    padding: {spacing.md}px;
    border-bottom: 1px solid {c(colors.border_soft)};
}}

QTableWidget[role="file-table"] QHeaderView::section {{
    background-color: {c(colors.bg_panel)};
    color: {c(colors.text_secondary)};
    border: none;
    border-bottom: 1px solid {c(colors.border_default)};
    padding: {spacing.md}px;
    font-weight: 600;
}}

QFrame[role="file-tabs"] {{
    background-color: {c(colors.bg_base)};
    border: 1px solid {c(colors.border_default)};
    border-radius: {radius.pill}px;
}}

QPushButton[role="file-tab"] {{
    min-height: 34px;
    padding: 0 {spacing.md}px;
    border-radius: {radius.pill}px;
    border: 1px solid transparent;
    background-color: transparent;
    color: {c(colors.text_secondary)};
}}

QPushButton[role="file-tab"]:hover {{
    background-color: {c(colors.bg_subtle)};
    color: {c(colors.text_primary)};
}}

QPushButton[role="file-tab"][state="active"] {{
    background-color: {c(colors.bg_elevated)};
    color: {c(colors.text_primary)};
    border: 1px solid {c(colors.border_default)};
}}

QFrame[role="unlocked-card"] {{
    background-color: {c(colors.bg_elevated)};
    border: 1px solid {c(colors.border_soft)};
    border-radius: {radius.md}px;
}}

QFrame[role="unlocked-card"]:hover {{
    background-color: {c(colors.bg_subtle)};
    border: 1px solid {c(colors.border_selected)};
}}

QFrame[role="unlocked-card"][state="selected"] {{
    background-color: {c(colors.bg_subtle)};
    border: 1px solid {c(colors.border_selected)};
}}

QFrame[role="file-props-actions"] {{
    background-color: {c(colors.bg_subtle)};
    border: 1px solid {c(colors.border_default)};
    border-radius: {radius.md}px;
}}

QLabel[role="file-preview"] {{
    background-color: {c(colors.bg_elevated)};
    border: 1px solid {c(colors.border_default)};
    border-radius: {radius.sm}px;
    padding: {spacing.md}px;
    color: {c(colors.text_muted)};
}}

QFrame[role="file-footer"] {{
    background-color: {c(colors.bg_elevated)};
    border: 1px solid {c(colors.border_soft)};
    border-radius: {radius.md}px;
    border-top-left-radius: 0;
    border-top-right-radius: 0;
}}

QFrame[role="file-pill"] {{
    border-radius: {radius.pill}px;
    border: 1px solid transparent;
}}

QFrame[role="file-pill"][tone="success"] {{
    background-color: {c(colors.status_success_bg)};
    border-color: {c(colors.status_success_bg)};
    color: {c(colors.status_success_text)};
}}

QFrame[role="file-pill"][tone="info"] {{
    background-color: {c(colors.status_info_bg)};
    border-color: {c(colors.status_info_bg)};
    color: {c(colors.status_info_text)};
}}
"""
