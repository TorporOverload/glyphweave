"""Builders for component-level token specs: buttons, inputs, selection
controls, badges, and alerts."""

from __future__ import annotations

import dataclasses

from PySide6.QtGui import QColor

from ..types import (
    AlertSpec,
    AlertVariant,
    BadgeSpec,
    BadgeVariant,
    ButtonSpec,
    ButtonVariant,
    FieldVariant,
    InputSpec,
    Palette,
    Radius,
    SelectionControlSpec,
    SelectionVariant,
    SemanticColors,
    Sizes,
    Spacing,
    SurfaceColors,
)
from .colors import mix, transparent

_S = SurfaceColors


def build_buttons(
    *,
    colors: SemanticColors,
    palette: Palette,
    spacing: Spacing,
    radius: Radius,
    sizes: Sizes,
    field_border: QColor,
    field_border_hover: QColor,
    disabled_surface: QColor,
    disabled_text: QColor,
) -> dict[ButtonVariant, ButtonSpec]:
    t = transparent()
    return {
        ButtonVariant.PRIMARY: ButtonSpec(
            height=sizes.control_default,
            radius=radius.sm,
            padding_x=spacing.lg,
            gap=spacing.sm,
            default=_S(colors.action_primary_fill, colors.action_primary_text, t),
            hover=_S(
                mix(colors.action_primary_fill, palette.white, 0.06),
                colors.action_primary_text,
                t,
            ),
            pressed=_S(
                mix(colors.action_primary_fill, palette.white, 0.12),
                colors.action_primary_text,
                t,
            ),
            disabled=_S(
                mix(colors.action_primary_fill, colors.bg_base, 0.55),
                disabled_text,
                t,
            ),
            focus_ring=colors.focus_ring,
        ),
        ButtonVariant.SECONDARY: ButtonSpec(
            height=sizes.control_default,
            radius=radius.sm,
            padding_x=spacing.lg,
            gap=spacing.sm,
            default=_S(
                colors.action_secondary_fill,
                colors.action_secondary_text,
                field_border,
            ),
            hover=_S(
                colors.bg_subtle, colors.action_secondary_text, field_border_hover
            ),
            pressed=_S(
                mix(colors.action_secondary_fill, colors.text_primary, 0.04),
                colors.action_secondary_text,
                colors.border_default,
            ),
            disabled=_S(
                disabled_surface,
                disabled_text,
                mix(field_border, colors.bg_base, 0.35),
            ),
            focus_ring=colors.focus_ring,
        ),
        ButtonVariant.GHOST: ButtonSpec(
            height=sizes.control_default,
            radius=radius.sm,
            padding_x=spacing.md,
            gap=spacing.sm,
            default=_S(t, colors.action_ghost_text, colors.border_default),
            hover=_S(colors.bg_subtle, colors.text_primary, colors.border_selected),
            pressed=_S(
                mix(colors.bg_subtle, colors.text_primary, 0.04),
                colors.text_primary,
                colors.border_default,
            ),
            disabled=_S(t, disabled_text, field_border),
            focus_ring=colors.focus_ring,
        ),
        ButtonVariant.DANGER: ButtonSpec(
            height=sizes.control_default,
            radius=radius.sm,
            padding_x=spacing.lg,
            gap=spacing.sm,
            default=_S(colors.action_danger_fill, colors.action_danger_text, t),
            hover=_S(
                mix(colors.action_danger_fill, palette.white, 0.08),
                colors.action_danger_text,
                t,
            ),
            pressed=_S(
                mix(colors.action_danger_fill, palette.white, 0.14),
                colors.action_danger_text,
                t,
            ),
            disabled=_S(
                mix(colors.action_danger_fill, colors.bg_base, 0.55),
                mix(colors.action_danger_text, colors.bg_base, 0.25),
                t,
            ),
            focus_ring=colors.focus_ring,
        ),
        ButtonVariant.ICON: ButtonSpec(
            height=sizes.control_default,
            radius=radius.sm,
            padding_x=spacing.sm,
            gap=spacing.sm,
            default=_S(
                colors.action_secondary_fill,
                colors.text_secondary,
                colors.border_default,
            ),
            hover=_S(colors.bg_subtle, colors.text_primary, colors.border_selected),
            pressed=_S(
                mix(colors.bg_subtle, colors.text_primary, 0.04),
                colors.text_primary,
                colors.border_default,
            ),
            disabled=_S(disabled_surface, disabled_text, field_border),
            focus_ring=colors.focus_ring,
        ),
    }


def build_fields(
    *,
    colors: SemanticColors,
    spacing: Spacing,
    radius: Radius,
    sizes: Sizes,
    field_bg: QColor,
    field_border: QColor,
    field_border_hover: QColor,
    disabled_surface: QColor,
    disabled_text: QColor,
) -> dict[FieldVariant, InputSpec]:
    field_base = InputSpec(
        height=sizes.control_default,
        radius=radius.sm,
        padding_x=spacing.md,
        default=_S(field_bg, colors.text_primary, field_border),
        hover=_S(field_bg, colors.text_primary, field_border_hover),
        focus=_S(field_bg, colors.text_primary, colors.focus_ring),
        error=_S(field_bg, colors.text_primary, colors.border_error),
        disabled=_S(
            disabled_surface,
            disabled_text,
            mix(field_border, colors.bg_base, 0.35),
        ),
        read_only=_S(colors.bg_panel, colors.text_primary, field_border),
        placeholder=colors.text_muted,
        helper_text=colors.text_muted,
    )
    fields = {
        v: field_base
        for v in (
            FieldVariant.TEXT,
            FieldVariant.SEARCH,
            FieldVariant.PASSWORD,
            FieldVariant.SELECT,
        )
    }
    fields[FieldVariant.MULTILINE] = dataclasses.replace(
        field_base, height=sizes.control_large
    )
    return fields


def build_selections(
    *,
    colors: SemanticColors,
    spacing: Spacing,
    field_bg: QColor,
    field_border: QColor,
    field_border_hover: QColor,
    disabled_surface: QColor,
    disabled_text: QColor,
) -> dict[SelectionVariant, SelectionControlSpec]:
    base = SelectionControlSpec(
        indicator_size=18,
        gap=spacing.sm,
        default=_S(field_bg, colors.text_primary, field_border),
        hover=_S(field_bg, colors.text_primary, field_border_hover),
        focus=_S(field_bg, colors.text_primary, colors.focus_ring),
        checked=_S(
            colors.action_primary_fill,
            colors.action_primary_text,
            colors.action_primary_fill,
        ),
        disabled=_S(
            disabled_surface,
            disabled_text,
            mix(field_border, colors.bg_base, 0.35),
        ),
    )
    return {
        SelectionVariant.CHECKBOX: base,
        SelectionVariant.RADIO: base,
        SelectionVariant.SWITCH: dataclasses.replace(base, indicator_size=20),
    }


def build_badges(
    *, colors: SemanticColors, radius: Radius
) -> dict[BadgeVariant, BadgeSpec]:
    t = transparent()

    def _badge(bg: QColor, fg: QColor, border: QColor | None = None) -> BadgeSpec:
        return BadgeSpec(22, radius.pill, 10, 6, _S(bg, fg, border or t))

    return {
        BadgeVariant.NEUTRAL: _badge(
            colors.status_neutral_bg, colors.status_neutral_text
        ),
        BadgeVariant.INFO: _badge(colors.status_info_bg, colors.status_info_text),
        BadgeVariant.SUCCESS: _badge(
            colors.status_success_bg, colors.status_success_text
        ),
        BadgeVariant.WARNING: _badge(
            colors.status_warning_bg, colors.status_warning_text
        ),
        BadgeVariant.WARNING_STRONG: _badge(
            colors.status_warning_strong_bg, colors.status_warning_strong_text
        ),
        BadgeVariant.ERROR: _badge(colors.status_error_bg, colors.status_error_text),
        BadgeVariant.CONFLICT: _badge(
            colors.status_warning_strong_bg,
            colors.status_warning_strong_text,
            colors.status_special_bg,
        ),
        BadgeVariant.METADATA: _badge(colors.bg_panel, colors.text_secondary),
    }


def build_alerts(
    *, colors: SemanticColors, radius: Radius, spacing: Spacing
) -> dict[AlertVariant, AlertSpec]:
    t = transparent()

    def _alert(bg: QColor, fg: QColor, border: QColor | None = None) -> AlertSpec:
        return AlertSpec(
            radius.md, spacing.lg, spacing.md, spacing.sm, _S(bg, fg, border or t)
        )

    return {
        AlertVariant.INFO: _alert(colors.status_info_bg, colors.status_info_text),
        AlertVariant.SUCCESS: _alert(
            colors.status_success_bg, colors.status_success_text
        ),
        AlertVariant.WARNING: _alert(
            colors.status_warning_bg, colors.status_warning_text
        ),
        AlertVariant.WARNING_STRONG: _alert(
            colors.status_warning_strong_bg, colors.status_warning_strong_text
        ),
        AlertVariant.ERROR: _alert(
            colors.status_error_bg, colors.status_error_text
        ),
        AlertVariant.CONFLICT: _alert(
            colors.status_warning_strong_bg,
            colors.status_warning_strong_text,
            colors.status_special_bg,
        ),
    }
