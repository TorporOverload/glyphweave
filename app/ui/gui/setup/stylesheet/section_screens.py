"""Screen + modal containers, plus the splash / recovery / vault-list /
unlock-screen role styles."""

from __future__ import annotations

from .helpers import StyleCtx, c


def build(ctx: StyleCtx) -> str:
    colors = ctx.colors
    radius = ctx.radius
    spacing = ctx.spacing
    typography = ctx.typography
    secondary = ctx.secondary

    return f"""
/* ------ Screens ------ */

QWidget[role="empty-vault"] {{
    background-color: {c(colors.bg_base)};
}}

QWidget[role="recovery-phrase"] {{
    background-color: {c(colors.bg_base)};
}}

QWidget[role="vault-list"] {{
    background-color: {c(colors.bg_base)};
}}

QWidget[role="unlock-vault"] {{
    background-color: {c(colors.bg_base)};
}}

/* ------ Modals ------ */

QDialog[role="create-folder"] {{
    background-color: {c(colors.bg_panel)};
    border: 1px solid {c(colors.border_default)};
    border-radius: 28px;
}}

QLabel[role="create-folder-title"] {{
    color: {c(colors.text_primary)};
}}

QLineEdit[role="create-folder-field"] {{
    min-height: 60px;
    padding: 0 {spacing.lg}px;
    background-color: {c(colors.bg_elevated)};
    color: {c(colors.text_primary)};
    border: 2px solid {c(colors.focus_ring)};
    border-radius: {radius.sm}px;
    font-size: {typography.section_title.size_px}px;
}}

QLineEdit[role="create-folder-field"]:hover,
QLineEdit[role="create-folder-field"]:focus {{
    border: 2px solid {c(colors.focus_ring)};
}}

QFrame[role="create-vault-modal"] {{
    background-color: {c(colors.bg_panel)};
    border: 1px solid {c(colors.border_default)};
    border-radius: {radius.sm}px;
}}

QFrame[role="recovery-modal"] {{
    background-color: {c(colors.bg_panel)};
    border: 1px solid {c(colors.border_default)};
    border-radius: {radius.md}px;
}}

QFrame[role="vault-list-modal"] {{
    background-color: {c(colors.bg_panel)};
    border: 1px solid {c(colors.border_default)};
    border-radius: {radius.md}px;
}}

QFrame[role="unlock-modal"] {{
    background-color: {c(colors.bg_panel)};
    border: 1px solid {c(colors.border_default)};
    border-radius: 10px;
}}

/* ------ Splash / create-vault labels ------ */

QLabel[role="splash-copy"] {{
    color: {c(colors.text_secondary)};
}}

QLabel[role="create-vault-caption"] {{
    color: rgba(169, 180, 200, 1);
}}

QFrame[role="create-vault-divider"] {{
    background-color: rgba(169, 180, 200, 1);
    min-height: 1px;
    max-height: 1px;
}}

/* ------ Recovery ------ */

QFrame[role="recovery-divider"] {{
    background-color: {c(colors.border_default)};
    min-height: 1px;
    max-height: 1px;
}}

QFrame[role="recovery-short-divider"] {{
    background-color: rgba(169, 180, 200, 1);
    min-width: 100px;
    max-width: 100px;
    min-height: 1px;
    max-height: 1px;
}}

QLabel[role="recovery-mono"] {{
    color: {c(colors.border_default)};
}}

QLabel[role="recovery-warning"] {{
    color: {c(colors.text_secondary)};
}}

QLabel[role="recovery-hint"] {{
    color: rgba(169, 180, 200, 1);
}}

QFrame[role="recovery-pill"] {{
    background-color: {c(colors.bg_base)};
    border: 1px solid {c(colors.border_default)};
    border-radius: {radius.sm}px;
}}

QLabel[role="recovery-number"] {{
    color: {c(colors.text_muted)};
}}

QCheckBox[role="recovery-check"] {{
    min-height: 30px;
    padding: 0 {spacing.sm}px;
    border: 1px solid {c(colors.border_default)};
    border-radius: {radius.sm}px;
    background-color: {c(colors.bg_base)};
    color: {c(colors.text_primary)};
    font-size: 11px;
}}

QCheckBox[role="recovery-check"]::indicator {{
    width: 12px;
    height: 12px;
    border: 1px solid {c(colors.border_default)};
    background: transparent;
}}

QCheckBox[role="recovery-check"]::indicator:checked {{
    background-color: {c(colors.action_primary_fill)};
    border: 1px solid {c(colors.action_primary_fill)};
}}

/* ------ Vault list ------ */

QLabel[role="vault-intro"],
QLabel[role="vault-footer"],
QLabel[role="unlock-intro"] {{
    color: rgba(169, 180, 200, 1);
}}

QLabel[role="vault-subtitle"] {{
    color: rgba(169, 180, 200, 1);
}}

QLabel[role="vault-path"] {{
    color: #858c9b;
}}

QLabel[role="vault-timestamp"] {{
    color: rgba(169, 180, 200, 1);
}}

QLabel[role="vault-indicator"] {{
    background-color: {c(colors.border_default)};
    border-radius: 3px;
}}

QPushButton[role="vault-item"] {{
    background-color: {c(colors.bg_base)};
    color: {c(colors.text_primary)};
    border: 1px solid {c(colors.border_default)};
    border-radius: {radius.sm}px;
    padding: 0;
    text-align: left;
}}

QPushButton[role="vault-item"]:hover {{
    background-color: {c(colors.bg_panel)};
    border: 1px solid {c(colors.border_selected)};
}}

QPushButton[role="vault-item"]:pressed {{
    background-color: {c(secondary.pressed.bg)};
}}

/* link-style buttons: vault-link shares base style with unlock variants */
QPushButton[role="vault-link"],
QPushButton[role="unlock-back"],
QPushButton[role="unlock-forgot"] {{
    min-height: 22px;
    padding: 0;
    border: none;
    background: transparent;
    color: #6d7d99;
}}

QPushButton[role="vault-link"]:hover,
QPushButton[role="unlock-back"]:hover,
QPushButton[role="unlock-forgot"]:hover {{
    color: {c(colors.text_secondary)};
    text-decoration: underline;
}}

QPushButton[role="vault-link"]:pressed,
QPushButton[role="unlock-back"]:pressed,
QPushButton[role="unlock-forgot"]:pressed {{
    color: {c(colors.text_primary)};
}}

QPushButton[role="vault-link"]:focus,
QPushButton[role="unlock-back"]:focus,
QPushButton[role="unlock-forgot"]:focus {{
    border: none;
}}

/* Back and forgot have their own mono-style overrides */
QPushButton[role="unlock-back"] {{
    color: #434c5e;
    font-size: 12px;
    font-family: "{typography.family_mono}";
}}

QPushButton[role="unlock-forgot"] {{
    color: rgba(169, 180, 200, 1);
    font-size: 12px;
    font-family: "{typography.family_mono}";
}}

/* ------ Unlock ------ */

QLabel[role="unlock-path"] {{
    color: #858c9b;
}}

QLabel[role="error-text"] {{
    color: {c(colors.status_error_text)};
}}
"""
