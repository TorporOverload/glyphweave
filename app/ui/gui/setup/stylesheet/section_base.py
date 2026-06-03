"""Base styles + button variants applied first so later sections can
override on a per-role basis."""

from __future__ import annotations

from .helpers import StyleCtx, c


def build(ctx: StyleCtx) -> str:
    colors = ctx.colors
    radius = ctx.radius
    spacing = ctx.spacing
    sizes = ctx.sizes
    typography = ctx.typography
    primary = ctx.primary
    secondary = ctx.secondary
    ghost = ctx.ghost
    danger = ctx.danger

    return f"""
QWidget {{
    background-color: {c(colors.bg_base)};
    color: {c(colors.text_primary)};
    font-family: "{typography.family_ui}";
    font-size: {typography.body.size_px}px;
}}

QMainWindow {{
    background-color: {c(colors.bg_base)};
}}

QLabel {{
    background: transparent;
}}

QLabel[tone="muted"] {{
    color: {c(colors.text_muted)};
}}

QFrame[role="card"] {{
    background-color: {c(colors.bg_elevated)};
    border: 1px solid {c(colors.border_soft)};
    border-radius: {radius.md}px;
}}

QFrame[role="separator"] {{
    background-color: {c(colors.border_soft)};
    min-height: 1px;
    max-height: 1px;
}}

QPushButton {{
    min-height: {sizes.control_default}px;
    padding: 0 {spacing.lg}px;
    border-radius: {radius.sm}px;
    border: 1px solid transparent;
    font-size: {typography.button.size_px}px;
    font-weight: 500;
}}

QPushButton[size="sm"] {{
    min-height: {sizes.control_compact}px;
    padding: 0 {spacing.md}px;
}}

QPushButton[size="lg"] {{
    min-height: {sizes.control_large}px;
    padding: 0 {spacing.xl}px;
}}

QPushButton:focus {{
    border: 1px solid {c(colors.focus_ring)};
}}

QPushButton[variant="primary"] {{
    background-color: {c(colors.action_primary_fill)};
    color: {c(colors.action_primary_text)};
}}

QPushButton[variant="primary"]:hover {{
    background-color: {c(primary.hover.bg)};
}}

QPushButton[variant="primary"]:pressed {{
    background-color: {c(primary.pressed.bg)};
}}

QPushButton[variant="primary"]:disabled {{
    background-color: {c(primary.disabled.bg)};
    color: {c(primary.disabled.fg)};
}}

QPushButton[variant="secondary"] {{
    background-color: {c(colors.action_secondary_fill)};
    color: {c(colors.action_secondary_text)};
    border: 1px solid {c(colors.border_default)};
}}

QPushButton[variant="secondary"]:hover {{
    background-color: {c(secondary.hover.bg)};
}}

QPushButton[variant="secondary"]:pressed {{
    background-color: {c(secondary.pressed.bg)};
}}

QPushButton[variant="secondary"]:disabled {{
    background-color: {c(secondary.disabled.bg)};
    color: {c(secondary.disabled.fg)};
}}

QPushButton[variant="ghost"] {{
    background-color: transparent;
    color: {c(colors.action_ghost_text)};
    border: 1px solid {c(colors.border_default)};
}}

QPushButton[variant="icon"] {{
    background-color: {c(colors.action_secondary_fill)};
    color: {c(colors.text_secondary)};
    border: 1px solid {c(colors.border_default)};
}}

QPushButton[variant="ghost"]:hover,
QPushButton[variant="icon"]:hover {{
    background-color: {c(ghost.hover.bg)};
    color: {c(ghost.hover.fg)};
    border: 1px solid {c(colors.border_selected)};
}}

QPushButton[variant="ghost"]:pressed,
QPushButton[variant="icon"]:pressed {{
    background-color: {c(ghost.pressed.bg)};
    color: {c(ghost.pressed.fg)};
    border: 1px solid {c(colors.border_default)};
}}

QPushButton[variant="danger"] {{
    background-color: {c(colors.action_danger_fill)};
    color: {c(colors.action_danger_text)};
}}

QPushButton[variant="danger"]:hover {{
    background-color: {c(danger.hover.bg)};
}}

QPushButton[variant="danger"]:pressed {{
    background-color: {c(danger.pressed.bg)};
}}
"""
