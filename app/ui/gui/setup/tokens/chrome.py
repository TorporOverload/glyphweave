"""Builders for the typography stack, application chrome (sidebar/topbar/tab
nav), and the status-key registry."""

from __future__ import annotations

from PySide6.QtGui import QFont

from ..types import (
    AlertVariant,
    BadgeVariant,
    Radius,
    SemanticColors,
    SidebarNavSpec,
    Sizes,
    StatusKey,
    StatusSpec,
    SurfaceColors,
    TabNavSpec,
    TextStyle,
    TopBarSpec,
    Typography,
)
from .colors import mix, transparent

_S = SurfaceColors


def build_typography() -> Typography:
    return Typography(
        family_ui="IBM Plex Sans",
        family_mono="IBM Plex Mono",
        family_dv="AK Rasmee",
        app_title=TextStyle("IBM Plex Sans", 28, QFont.Weight.DemiBold, 1.2),
        page_title=TextStyle("IBM Plex Sans", 24, QFont.Weight.DemiBold, 1.2),
        section_title=TextStyle("IBM Plex Sans", 18, QFont.Weight.DemiBold, 1.2),
        card_title=TextStyle("IBM Plex Sans", 16, QFont.Weight.Medium, 1.4),
        body=TextStyle("IBM Plex Sans", 14, QFont.Weight.Normal, 1.4),
        body_secondary=TextStyle("IBM Plex Sans", 13, QFont.Weight.Normal, 1.4),
        caption=TextStyle("IBM Plex Sans", 12, QFont.Weight.Normal, 1.4),
        button=TextStyle("IBM Plex Sans", 12, QFont.Weight.Medium, 1.2),
        input=TextStyle("IBM Plex Sans", 13, QFont.Weight.Normal, 1.4),
        badge=TextStyle("IBM Plex Sans", 9, QFont.Weight.DemiBold, 1.2),
        mono=TextStyle("IBM Plex Mono", 12, QFont.Weight.Normal, 1.4),
        dv_body=TextStyle("AK Rasmee", 14, QFont.Weight.Normal, 1.5),
    )


def build_sidebar_nav(
    *, colors: SemanticColors, sizes: Sizes, radius: Radius
) -> SidebarNavSpec:
    t = transparent()
    return SidebarNavSpec(
        width_min=sizes.sidebar_width_min,
        width_max=sizes.sidebar_width_max,
        item_height=42,
        item_radius=radius.sm,
        bg=colors.bg_panel,
        border=colors.border_default,
        item_default=_S(t, colors.text_secondary, t),
        item_hover=_S(colors.bg_subtle, colors.text_primary, colors.border_default),
        item_active=_S(colors.bg_base, colors.text_primary, colors.border_default),
        focus_ring=colors.focus_ring,
    )


def build_top_bar(*, colors: SemanticColors, sizes: Sizes) -> TopBarSpec:
    return TopBarSpec(
        height_min=sizes.topbar_height_min,
        height_max=sizes.topbar_height_max,
        bg=colors.bg_panel,
        border=colors.border_default,
        fg=colors.text_primary,
    )


def build_tabs(*, colors: SemanticColors) -> TabNavSpec:
    t = transparent()
    return TabNavSpec(
        height=38,
        default=_S(t, colors.text_secondary, t),
        hover=_S(
            mix(colors.bg_subtle, colors.text_primary, 0.04),
            colors.text_primary,
            t,
        ),
        active=_S(t, colors.text_primary, colors.border_selected),
        focus_ring=colors.focus_ring,
    )


def build_statuses() -> dict[StatusKey, StatusSpec]:
    return {
        StatusKey.LOCKED: StatusSpec("Locked", "lock", BadgeVariant.NEUTRAL),
        StatusKey.UNLOCK_ERROR: StatusSpec(
            "Unlock failed", "circle-xmark", BadgeVariant.ERROR, AlertVariant.ERROR
        ),
        StatusKey.READY: StatusSpec("Ready", "circle-check", BadgeVariant.SUCCESS),
        StatusKey.SYNCED: StatusSpec(
            "Up to date", "circle-check", BadgeVariant.SUCCESS
        ),
        StatusKey.SYNCING: StatusSpec(
            "Syncing", "arrows-rotate", BadgeVariant.INFO, AlertVariant.INFO
        ),
        StatusKey.CONFLICT: StatusSpec(
            "Conflict",
            "arrows-left-right",
            BadgeVariant.CONFLICT,
            AlertVariant.CONFLICT,
        ),
    }
