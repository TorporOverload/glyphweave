from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QApplication, QWidget

from .stylesheet import build_stylesheet
from .tokens import (
    AlertVariant,
    BadgeVariant,
    ButtonVariant,
    SelectionVariant,
    TOKENS,
    TextStyle,
    ThemeTokens,
)
from .types import Role, Size, Tone, State


@dataclass(frozen=True, slots=True)
class ThemeContext:
    tokens: ThemeTokens
    palette: QPalette
    stylesheet: str


def _enum_value(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    return value


def refresh_widget_style(widget: QWidget) -> None:
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


def set_properties(widget: QWidget, **properties: object) -> None:
    for key, value in properties.items():
        widget.setProperty(key, _enum_value(value))
    refresh_widget_style(widget)


def apply_text_style(widget: QWidget, text_style: TextStyle) -> None:
    widget.setFont(text_style.qfont())

def apply_button(
    widget: QWidget,
    variant: ButtonVariant,
    *,
    role: Role | str | None = None,
    size: Size | str = Size.MD,
) -> None:
    props: dict[str, object] = {"variant": variant, "size": size}
    if role is not None:
        props["role"] = role
    set_properties(widget, **props)


def apply_field(
    widget: QWidget,
    *,
    role: Role | str | None = None,
    state: State | str | None = None,
) -> None:
    props: dict[str, object] = {"state": state}
    if role is not None:
        props["role"] = role
    set_properties(widget, **props)


def set_state(widget: QWidget, state: State | str | None) -> None:
    set_properties(widget, state=state)


def set_tone(widget: QWidget, tone: Tone | str) -> None:
    set_properties(widget, tone=tone)


def set_field_error(widget: QWidget, has_error: bool) -> None:
    set_state(widget, State.ERROR if has_error else None)


def apply_selection_variant(
    widget: QWidget,
    variant: SelectionVariant,
) -> None:
    set_properties(widget, variant=variant)


def apply_badge_variant(widget: QWidget, variant: BadgeVariant) -> None:
    set_properties(widget, role=Role.BADGE, tone=variant)


def apply_alert_variant(widget: QWidget, variant: AlertVariant) -> None:
    set_properties(widget, role=Role.ALERT, tone=variant)


def apply_card_style(widget: QWidget) -> None:
    set_properties(widget, role=Role.CARD)


def apply_sidebar_item_style(widget: QWidget, *, active: bool = False) -> None:
    set_properties(
        widget,
        role=Role.SIDEBAR_ITEM,
        state=State.ACTIVE if active else None,
    )


def build_palette(tokens: ThemeTokens = TOKENS) -> QPalette:
    colors = tokens.colors
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, colors.bg_base)
    palette.setColor(QPalette.ColorRole.WindowText, colors.text_primary)
    palette.setColor(QPalette.ColorRole.Base, colors.bg_elevated)
    palette.setColor(QPalette.ColorRole.AlternateBase, colors.bg_subtle)
    palette.setColor(QPalette.ColorRole.ToolTipBase, colors.bg_elevated)
    palette.setColor(QPalette.ColorRole.ToolTipText, colors.text_primary)
    palette.setColor(QPalette.ColorRole.Text, colors.text_primary)
    palette.setColor(QPalette.ColorRole.Button, colors.action_secondary_fill)
    palette.setColor(QPalette.ColorRole.ButtonText, colors.text_primary)
    palette.setColor(QPalette.ColorRole.BrightText, colors.text_inverse)
    palette.setColor(QPalette.ColorRole.Highlight, colors.action_primary_fill)
    palette.setColor(
        QPalette.ColorRole.HighlightedText,
        colors.action_primary_text,
    )
    palette.setColor(
        QPalette.ColorRole.PlaceholderText,
        colors.text_muted,
    )
    return palette


def apply_theme(
    app: QApplication,
    tokens: ThemeTokens = TOKENS,
) -> ThemeContext:
    palette = build_palette(tokens)
    stylesheet = build_stylesheet(tokens)
    app.setPalette(palette)
    app.setFont(tokens.typography.body.qfont())
    app.setStyleSheet(stylesheet)
    return ThemeContext(tokens=tokens, palette=palette, stylesheet=stylesheet)