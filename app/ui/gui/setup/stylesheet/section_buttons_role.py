
from __future__ import annotations

from .helpers import StyleCtx, c


def build(ctx: StyleCtx) -> str:
    colors = ctx.colors
    radius = ctx.radius
    spacing = ctx.spacing
    primary = ctx.primary
    secondary = ctx.secondary

    return f"""
/* ------ Create-vault buttons ------ */

QPushButton[variant="primary"][role="create-vault"] {{
    min-height: 36px;
    padding: 0 20px;
    border-radius: {radius.sm}px;
    border: 1px solid transparent;
    background-color: {c(colors.action_primary_fill)};
    color: {c(colors.action_primary_text)};
    font-size: 14px;
    font-weight: 500;
}}

QPushButton[variant="primary"][role="create-vault"]:hover {{
    background-color: {c(primary.hover.bg)};
}}

QPushButton[variant="primary"][role="create-vault"]:pressed {{
    background-color: {c(primary.pressed.bg)};
}}

QPushButton[variant="secondary"][role="create-vault"] {{
    min-height: 36px;
    padding: 0 20px;
    border-radius: {radius.sm}px;
    border: 1px solid {c(colors.border_default)};
    background-color: {c(colors.action_secondary_fill)};
    color: {c(colors.action_secondary_text)};
    font-size: 14px;
    font-weight: 400;
}}

QPushButton[variant="secondary"][role="create-vault"]:hover {{
    background-color: {c(secondary.hover.bg)};
}}

QPushButton[variant="secondary"][role="create-vault"]:pressed {{
    background-color: {c(secondary.pressed.bg)};
}}

QPushButton[variant="icon"][role="create-vault"] {{
    min-height: 36px;
    max-height: 36px;
    min-width: 36px;
    max-width: 36px;
    padding: 0;
    border-radius: {radius.sm}px;
    border: 1px solid {c(colors.border_default)};
    background-color: {c(colors.action_secondary_fill)};
    color: {c(colors.text_secondary)};
}}

QPushButton[variant="icon"][role="create-vault"]:hover {{
    background-color: {c(secondary.hover.bg)};
    border: 1px solid {c(colors.border_selected)};
}}

QPushButton[variant="icon"][role="create-vault"]:pressed {{
    background-color: {c(secondary.pressed.bg)};
}}

QLineEdit[role="create-vault-field"] {{
    min-height: 36px;
    padding: 0 {spacing.md}px;
    background-color: {c(colors.bg_base)};
    color: {c(colors.text_primary)};
    border: 1px solid {c(colors.border_default)};
    border-radius: 6px;
}}

QLineEdit[role="create-vault-field"]:hover {{
    border: 1px solid {c(colors.border_selected)};
}}

QLineEdit[role="create-vault-field"]:focus {{
    border: 1px solid {c(colors.focus_ring)};
}}

/* ------ Recovery buttons ------ */

QPushButton[variant="primary"][role="recovery"] {{
    min-height: 36px;
    padding: 0 20px;
    border-radius: {radius.md}px;
    border: 1px solid transparent;
    background-color: {c(colors.action_primary_fill)};
    color: {c(colors.action_primary_text)};
    font-size: 14px;
    font-weight: 400;
}}

QPushButton[variant="primary"][role="recovery"]:hover {{
    background-color: {c(primary.hover.bg)};
}}

QPushButton[variant="primary"][role="recovery"]:pressed {{
    background-color: {c(primary.pressed.bg)};
}}

QPushButton[variant="primary"][role="recovery"]:disabled {{
    background-color: {c(colors.bg_base)};
    color: rgba(169, 180, 200, 1);
    border: 1px solid #6d7d99;
}}

QPushButton[variant="secondary"][role="recovery"] {{
    min-height: 36px;
    padding: 0 20px;
    border-radius: {radius.md}px;
    border: 1px solid {c(colors.border_default)};
    background-color: {c(colors.bg_base)};
    color: {c(colors.text_secondary)};
    font-size: 14px;
    font-weight: 400;
}}

QPushButton[variant="secondary"][role="recovery"]:hover {{
    background-color: {c(secondary.hover.bg)};
}}

QPushButton[variant="secondary"][role="recovery"]:pressed {{
    background-color: {c(secondary.pressed.bg)};
}}

/* ------ Unlock primary button ------ */

QPushButton[variant="primary"][role="unlock"] {{
    min-height: 40px;
    padding: 0 20px;
    border-radius: {radius.md}px;
    border: 1px solid transparent;
    background-color: {c(colors.action_primary_fill)};
    color: {c(colors.action_primary_text)};
    font-size: 14px;
    font-weight: 400;
}}

QPushButton[variant="primary"][role="unlock"]:hover {{
    background-color: {c(primary.hover.bg)};
}}

QPushButton[variant="primary"][role="unlock"]:pressed {{
    background-color: {c(primary.pressed.bg)};
}}

QPushButton[variant="primary"][role="unlock"]:disabled {{
    background-color: {c(primary.disabled.bg)};
    color: {c(primary.disabled.fg)};
}}
"""
