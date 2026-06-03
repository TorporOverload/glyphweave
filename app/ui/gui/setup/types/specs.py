from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtGui import QColor, QFont

from .enums import (
    AlertVariant,
    BadgeVariant,
    ButtonVariant,
    FieldVariant,
    SelectionVariant,
    StatusKey,
)


@dataclass(frozen=True, slots=True)
class TextStyle:
    family: str
    size_px: int
    weight: QFont.Weight
    line_height: float

    def qfont(self, *, family: str | None = None) -> QFont:
        font = QFont(family or self.family)
        font.setPixelSize(self.size_px)
        font.setWeight(self.weight)
        return font


@dataclass(frozen=True, slots=True)
class SurfaceColors:
    bg: QColor
    fg: QColor
    border: QColor


@dataclass(frozen=True, slots=True)
class ButtonSpec:
    height: int
    radius: int
    padding_x: int
    gap: int
    default: SurfaceColors
    hover: SurfaceColors
    pressed: SurfaceColors
    disabled: SurfaceColors
    focus_ring: QColor


@dataclass(frozen=True, slots=True)
class InputSpec:
    height: int
    radius: int
    padding_x: int
    default: SurfaceColors
    hover: SurfaceColors
    focus: SurfaceColors
    error: SurfaceColors
    disabled: SurfaceColors
    read_only: SurfaceColors
    placeholder: QColor
    helper_text: QColor


@dataclass(frozen=True, slots=True)
class SelectionControlSpec:
    indicator_size: int
    gap: int
    default: SurfaceColors
    hover: SurfaceColors
    focus: SurfaceColors
    checked: SurfaceColors
    disabled: SurfaceColors


@dataclass(frozen=True, slots=True)
class BadgeSpec:
    height: int
    radius: int
    padding_x: int
    gap: int
    colors: SurfaceColors


@dataclass(frozen=True, slots=True)
class AlertSpec:
    radius: int
    padding: int
    gap_icon_content: int
    gap_title_body: int
    colors: SurfaceColors


@dataclass(frozen=True, slots=True)
class SidebarNavSpec:
    width_min: int
    width_max: int
    item_height: int
    item_radius: int
    bg: QColor
    border: QColor
    item_default: SurfaceColors
    item_hover: SurfaceColors
    item_active: SurfaceColors
    focus_ring: QColor


@dataclass(frozen=True, slots=True)
class TopBarSpec:
    height_min: int
    height_max: int
    bg: QColor
    border: QColor
    fg: QColor


@dataclass(frozen=True, slots=True)
class TabNavSpec:
    height: int
    default: SurfaceColors
    hover: SurfaceColors
    active: SurfaceColors
    focus_ring: QColor


@dataclass(frozen=True, slots=True)
class StatusSpec:
    label: str
    icon_name: str
    badge_variant: BadgeVariant
    alert_variant: AlertVariant | None = None


@dataclass(frozen=True, slots=True)
class Palette:
    nord0: QColor
    nord1: QColor
    nord2: QColor
    nord3: QColor
    nord4: QColor
    nord5: QColor
    nord6: QColor
    nord7: QColor
    nord8: QColor
    nord9: QColor
    nord10: QColor
    nord11: QColor
    nord12: QColor
    nord13: QColor
    nord14: QColor
    nord15: QColor
    warning_strong: QColor
    error_accessible: QColor
    info_accessible: QColor
    special_accessible: QColor
    white: QColor


@dataclass(frozen=True, slots=True)
class SemanticColors:
    bg_base: QColor
    bg_subtle: QColor
    bg_panel: QColor
    bg_elevated: QColor
    bg_overlay: QColor
    text_primary: QColor
    text_secondary: QColor
    text_muted: QColor
    text_inverse: QColor
    text_on_success: QColor
    text_on_warning: QColor
    text_on_warning_strong: QColor
    text_on_error: QColor
    text_on_info: QColor
    border_default: QColor
    border_soft: QColor
    border_selected: QColor
    border_error: QColor
    action_primary_fill: QColor
    action_primary_text: QColor
    action_secondary_fill: QColor
    action_secondary_text: QColor
    action_ghost_text: QColor
    action_danger_fill: QColor
    action_danger_text: QColor
    focus_ring: QColor
    status_success_bg: QColor
    status_success_text: QColor
    status_warning_bg: QColor
    status_warning_text: QColor
    status_warning_strong_bg: QColor
    status_warning_strong_text: QColor
    status_error_bg: QColor
    status_error_text: QColor
    status_info_bg: QColor
    status_info_text: QColor
    status_special_bg: QColor
    status_special_text: QColor
    status_neutral_bg: QColor
    status_neutral_text: QColor


@dataclass(frozen=True, slots=True)
class Typography:
    family_ui: str
    family_mono: str
    family_dv: str
    app_title: TextStyle
    page_title: TextStyle
    section_title: TextStyle
    card_title: TextStyle
    body: TextStyle
    body_secondary: TextStyle
    caption: TextStyle
    button: TextStyle
    input: TextStyle
    badge: TextStyle
    mono: TextStyle
    dv_body: TextStyle


@dataclass(frozen=True, slots=True)
class Spacing:
    xs: int = 4
    sm: int = 8
    md: int = 12
    lg: int = 16
    xl: int = 24
    xxl: int = 32
    xxxl: int = 48


@dataclass(frozen=True, slots=True)
class Radius:
    sm: int = 6
    md: int = 8
    lg: int = 12
    pill: int = 999


@dataclass(frozen=True, slots=True)
class Sizes:
    control_compact: int = 30
    control_default: int = 34
    control_large: int = 40
    icon_sm: int = 14
    icon_md: int = 16
    icon_lg: int = 20
    sidebar_width_min: int = 200
    sidebar_width_max: int = 200
    topbar_height_min: int = 36
    topbar_height_max: int = 40
    inspector_width_min: int = 260
    inspector_width_max: int = 260


@dataclass(frozen=True, slots=True)
class Motion:
    hover_ms: int = 100
    panel_ms: int = 220
    dialog_ms: int = 200
    toast_ms: int = 180


@dataclass(frozen=True, slots=True)
class ThemeTokens:
    palette: Palette
    colors: SemanticColors
    typography: Typography
    spacing: Spacing
    radius: Radius
    sizes: Sizes
    motion: Motion
    buttons: dict[ButtonVariant, ButtonSpec]
    fields: dict[FieldVariant, InputSpec]
    selections: dict[SelectionVariant, SelectionControlSpec]
    badges: dict[BadgeVariant, BadgeSpec]
    alerts: dict[AlertVariant, AlertSpec]
    sidebar_nav: SidebarNavSpec
    top_bar: TopBarSpec
    tabs: TabNavSpec
    statuses: dict[StatusKey, StatusSpec]
