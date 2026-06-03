"""Tail sections - badges, alerts, tab bar, and a final round of vault-list /
unlock / splash overrides that run last so they win over earlier rules."""

from __future__ import annotations

from .helpers import StyleCtx, c


def build(ctx: StyleCtx) -> str:
    colors = ctx.colors
    radius = ctx.radius
    spacing = ctx.spacing
    typography = ctx.typography

    return f"""
/* ------ Badges ------ */

QLabel[role="badge"] {{
    min-height: 22px;
    padding: 0 10px;
    border-radius: {radius.pill}px;
    font-size: {typography.badge.size_px}px;
    font-weight: 500;
}}

QLabel[role="badge"][tone="neutral"] {{
    background-color: {c(colors.status_neutral_bg)};
    color: {c(colors.status_neutral_text)};
}}

QLabel[role="badge"][tone="info"] {{
    background-color: {c(colors.status_info_bg)};
    color: {c(colors.status_info_text)};
}}

QLabel[role="badge"][tone="success"] {{
    background-color: {c(colors.status_success_bg)};
    color: {c(colors.status_success_text)};
}}

QLabel[role="badge"][tone="warning"] {{
    background-color: {c(colors.status_warning_bg)};
    color: {c(colors.status_warning_text)};
}}

QLabel[role="badge"][tone="warning-strong"],
QLabel[role="badge"][tone="conflict"] {{
    background-color: {c(colors.status_warning_strong_bg)};
    color: {c(colors.status_warning_strong_text)};
}}

QLabel[role="badge"][tone="error"] {{
    background-color: {c(colors.status_error_bg)};
    color: {c(colors.status_error_text)};
}}

QLabel[role="badge"][tone="metadata"] {{
    background-color: {c(colors.bg_panel)};
    color: {c(colors.text_secondary)};
}}

/* ------ Alerts ------ */

QFrame[role="alert"] {{
    border-radius: {radius.md}px;
    border: 1px solid transparent;
}}

QFrame[role="alert"][tone="info"] {{
    background-color: {c(colors.status_info_bg)};
    color: {c(colors.status_info_text)};
}}

QFrame[role="alert"][tone="success"] {{
    background-color: {c(colors.status_success_bg)};
    color: {c(colors.status_success_text)};
}}

QFrame[role="alert"][tone="warning"] {{
    background-color: {c(colors.status_warning_bg)};
    color: {c(colors.status_warning_text)};
}}

QFrame[role="alert"][tone="warning-strong"],
QFrame[role="alert"][tone="conflict"] {{
    background-color: {c(colors.status_warning_strong_bg)};
    color: {c(colors.status_warning_strong_text)};
}}

QFrame[role="alert"][tone="error"] {{
    background-color: {c(colors.status_error_bg)};
    border: 1px solid {c(colors.border_error)};
    color: {c(colors.status_error_text)};
}}

/* ------ Tab bar ------ */

QTabBar::tab {{
    min-height: 38px;
    padding: 0 {spacing.lg}px;
    margin-right: {spacing.sm}px;
    border-bottom: 2px solid transparent;
    color: {c(colors.text_secondary)};
}}

QTabBar::tab:selected {{
    color: {c(colors.text_primary)};
    border-bottom: 2px solid {c(colors.border_selected)};
}}

/* ------ Vault list ------ */

QPushButton[role="vault-item"] {{
    background-color: {c(colors.bg_base)};
    border: 1px solid {c(colors.border_default)};
    border-radius: {radius.sm}px;
    text-align: left;
}}

QPushButton[role="vault-item"]:hover {{
    background-color: {c(colors.bg_elevated)};
    border-color: {c(colors.border_soft)};
}}

QPushButton[role="vault-item"]:pressed {{
    background-color: {c(colors.bg_subtle)};
}}

QLabel[role="vault-timestamp"] {{
    color: {c(colors.text_muted)};
    font-family: "IBM Plex Mono";
}}

QLabel[role="vault-path"] {{
    color: {c(colors.text_muted)};
}}

/* ------ Unlock screen ------ */

QLabel[role="unlock-path"] {{
    color: {c(colors.text_muted)};
    font-family: "IBM Plex Mono";
}}

/* ------ Splash / welcome ------ */

QLabel[role="splash-copy"] {{
    color: {c(colors.text_secondary)};
}}
"""
