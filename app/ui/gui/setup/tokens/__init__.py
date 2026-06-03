from __future__ import annotations

from typing import Final

from ..types import (  # re-exported for callers (e.g. stylesheet.py)
    AlertSpec,
    AlertVariant,
    BadgeSpec,
    BadgeVariant,
    ButtonSpec,
    ButtonVariant,
    FieldVariant,
    InputSpec,
    Motion,
    Palette,
    Radius,
    SelectionControlSpec,
    SelectionVariant,
    SemanticColors,
    SidebarNavSpec,
    Sizes,
    Spacing,
    StatusKey,
    StatusSpec,
    SurfaceColors,
    TabNavSpec,
    TextStyle,
    ThemeTokens,
    TopBarSpec,
    Typography,
)
from .chrome import (
    build_sidebar_nav,
    build_statuses,
    build_tabs,
    build_top_bar,
    build_typography,
)
from .colors import (
    build_palette,
    build_semantic_colors,
    mix,
    qcolor_mix,
    to_css_color,
)
from .components import (
    build_alerts,
    build_badges,
    build_buttons,
    build_fields,
    build_selections,
)


def _build_tokens() -> ThemeTokens:
    palette = build_palette()
    colors = build_semantic_colors(palette)
    typography = build_typography()
    spacing = Spacing()
    radius = Radius()
    sizes = Sizes()
    motion = Motion()

    field_bg = colors.bg_base
    field_border = colors.border_default
    field_border_hover = colors.border_selected
    disabled_surface = mix(colors.bg_panel, colors.bg_base, 0.5)
    disabled_text = mix(colors.text_secondary, colors.bg_base, 0.45)

    buttons = build_buttons(
        colors=colors,
        palette=palette,
        spacing=spacing,
        radius=radius,
        sizes=sizes,
        field_border=field_border,
        field_border_hover=field_border_hover,
        disabled_surface=disabled_surface,
        disabled_text=disabled_text,
    )
    fields = build_fields(
        colors=colors,
        spacing=spacing,
        radius=radius,
        sizes=sizes,
        field_bg=field_bg,
        field_border=field_border,
        field_border_hover=field_border_hover,
        disabled_surface=disabled_surface,
        disabled_text=disabled_text,
    )
    selections = build_selections(
        colors=colors,
        spacing=spacing,
        field_bg=field_bg,
        field_border=field_border,
        field_border_hover=field_border_hover,
        disabled_surface=disabled_surface,
        disabled_text=disabled_text,
    )
    badges = build_badges(colors=colors, radius=radius)
    alerts = build_alerts(colors=colors, radius=radius, spacing=spacing)
    sidebar_nav = build_sidebar_nav(colors=colors, sizes=sizes, radius=radius)
    top_bar = build_top_bar(colors=colors, sizes=sizes)
    tabs = build_tabs(colors=colors)
    statuses = build_statuses()

    return ThemeTokens(
        palette=palette,
        colors=colors,
        typography=typography,
        spacing=spacing,
        radius=radius,
        sizes=sizes,
        motion=motion,
        buttons=buttons,
        fields=fields,
        selections=selections,
        badges=badges,
        alerts=alerts,
        sidebar_nav=sidebar_nav,
        top_bar=top_bar,
        tabs=tabs,
        statuses=statuses,
    )


TOKENS: Final[ThemeTokens] = _build_tokens()


__all__ = [
    "TOKENS",
    "to_css_color",
    "qcolor_mix",
    # Type re-exports (preserve the historical import surface).
    "AlertSpec",
    "AlertVariant",
    "BadgeSpec",
    "BadgeVariant",
    "ButtonSpec",
    "ButtonVariant",
    "FieldVariant",
    "InputSpec",
    "Motion",
    "Palette",
    "Radius",
    "SelectionControlSpec",
    "SelectionVariant",
    "SemanticColors",
    "SidebarNavSpec",
    "Sizes",
    "Spacing",
    "StatusKey",
    "StatusSpec",
    "SurfaceColors",
    "TabNavSpec",
    "TextStyle",
    "ThemeTokens",
    "TopBarSpec",
    "Typography",
]
