"""QColor helpers and palette/semantic-colour builders for the design tokens."""

from __future__ import annotations

from PySide6.QtGui import QColor

from ..types import Palette, SemanticColors


def qcolor_mix(value: str, *, alpha: float = 1.0) -> QColor:
    """Convert a colour string to a QColor with optional alpha transparency.

    Args:
        value: Colour string in any format ``QColor`` accepts (typically a
            ``#rrggbb`` hex code).
        alpha: Alpha between 0.0 (fully transparent) and 1.0 (fully opaque).

    Raises:
        ValueError: If ``value`` is not a valid colour string.
    """
    color = QColor(value)
    if not color.isValid():
        raise ValueError(f"Invalid color value: {value}")
    color.setAlpha(round(max(0.0, min(alpha, 1.0)) * 255))
    return color


def mix(left: QColor, right: QColor, amount: float) -> QColor:
    """Linearly interpolate between two colours by ``amount`` ∈ [0, 1]."""
    ratio = max(0.0, min(amount, 1.0))
    return QColor(
        round(left.red() + (right.red() - left.red()) * ratio),
        round(left.green() + (right.green() - left.green()) * ratio),
        round(left.blue() + (right.blue() - left.blue()) * ratio),
        round(left.alpha() + (right.alpha() - left.alpha()) * ratio),
    )


def transparent() -> QColor:
    return QColor(0, 0, 0, 0)


def to_css_color(color: QColor) -> str:
    """Render a QColor as a Qt-stylesheet-friendly colour string."""
    if color.alpha() == 255:
        return color.name(QColor.NameFormat.HexRgb)
    alpha = color.alpha() / 255
    return f"rgba({color.red()}, {color.green()}, {color.blue()}, {alpha:.3f})"


def build_palette() -> Palette:
    """Build the Nord-derived raw colour palette."""
    return Palette(
        nord0=qcolor_mix("#2e3440"),
        nord1=qcolor_mix("#3b4252"),
        nord2=qcolor_mix("#434c5e"),
        nord3=qcolor_mix("#4c566a"),
        nord4=qcolor_mix("#d8dee9"),
        nord5=qcolor_mix("#e5e9f0"),
        nord6=qcolor_mix("#eceff4"),
        nord7=qcolor_mix("#8fbcbb"),
        nord8=qcolor_mix("#88c0d0"),
        nord9=qcolor_mix("#81a1c1"),
        nord10=qcolor_mix("#5e81ac"),
        nord11=qcolor_mix("#bf616a"),
        nord12=qcolor_mix("#d08770"),
        nord13=qcolor_mix("#ebcb8b"),
        nord14=qcolor_mix("#a3be8c"),
        nord15=qcolor_mix("#b48ead"),
        warning_strong=qcolor_mix("#a0522d"),
        error_accessible=qcolor_mix("#bf616a"),
        info_accessible=qcolor_mix("#5e81ac"),
        special_accessible=qcolor_mix("#7d5c87"),
        white=qcolor_mix("#ffffff"),
    )


def build_semantic_colors(palette: Palette) -> SemanticColors:
    """Map raw palette entries to semantic role names used across the GUI."""
    return SemanticColors(
        bg_base=palette.nord4,
        bg_subtle=qcolor_mix("#dfe4ec"),
        bg_panel=palette.nord5,
        bg_elevated=palette.nord5,
        bg_overlay=qcolor_mix("#2e3440", alpha=0.35),
        text_primary=palette.nord0,
        text_secondary=palette.nord2,
        text_muted=qcolor_mix("#858c9b"),
        text_inverse=palette.white,
        text_on_success=qcolor_mix("#2e9961"),
        text_on_warning=qcolor_mix("#8a6d1a"),
        text_on_warning_strong=palette.warning_strong,
        text_on_error=palette.error_accessible,
        text_on_info=palette.info_accessible,
        border_default=palette.nord2,
        # Light-theme border tone: nord3 (#4c566a) is too dark for inline
        # 1px borders against light surfaces but #D8DEE9 is too pale -
        # this is the same `#C0C9D6` used by section_shell's BORDER_SOFT.
        border_soft=qcolor_mix("#c0c9d6"),
        border_selected=palette.nord9,
        border_error=palette.error_accessible,
        action_primary_fill=palette.nord1,
        action_primary_text=palette.white,
        action_secondary_fill=palette.nord4,
        action_secondary_text=palette.nord0,
        action_ghost_text=palette.nord2,
        action_danger_fill=palette.error_accessible,
        action_danger_text=palette.white,
        focus_ring=palette.nord9,
        status_success_bg=qcolor_mix("#2e9961", alpha=0.14),
        status_success_text=qcolor_mix("#2e9961"),
        status_warning_bg=qcolor_mix("#ebcb8b", alpha=0.20),
        status_warning_text=qcolor_mix("#8a6d1a"),
        status_warning_strong_bg=qcolor_mix("#d08770", alpha=0.18),
        status_warning_strong_text=palette.warning_strong,
        status_error_bg=qcolor_mix("#bf616a", alpha=0.15),
        status_error_text=palette.error_accessible,
        status_info_bg=qcolor_mix("#5e81ac", alpha=0.15),
        status_info_text=palette.info_accessible,
        status_special_bg=qcolor_mix("#b48ead", alpha=0.15),
        status_special_text=palette.special_accessible,
        status_neutral_bg=palette.nord4,
        status_neutral_text=palette.nord3,
    )
