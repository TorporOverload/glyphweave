from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..tokens import (
    ButtonVariant,
    FieldVariant,
    ThemeTokens,
    to_css_color,
)


def c(value) -> str:
    """Wrap :func:`to_css_color` for terse use inside QSS f-strings."""
    return to_css_color(value)


@dataclass(frozen=True, slots=True)
class StyleCtx:
    """Bundle of token slices that QSS section builders read from.

    Each section builder takes a single ``ctx`` instead of a long kwargs
    list, and pulls out whatever it needs (``ctx.colors``, ``ctx.primary``,
    etc.) with attribute access.
    """

    tokens: ThemeTokens
    colors: Any
    radius: Any
    spacing: Any
    sizes: Any
    typography: Any
    primary: Any
    secondary: Any
    ghost: Any
    danger: Any
    field: Any


def build_ctx(tokens: ThemeTokens) -> StyleCtx:
    return StyleCtx(
        tokens=tokens,
        colors=tokens.colors,
        radius=tokens.radius,
        spacing=tokens.spacing,
        sizes=tokens.sizes,
        typography=tokens.typography,
        primary=tokens.buttons[ButtonVariant.PRIMARY],
        secondary=tokens.buttons[ButtonVariant.SECONDARY],
        ghost=tokens.buttons[ButtonVariant.GHOST],
        danger=tokens.buttons[ButtonVariant.DANGER],
        field=tokens.fields[FieldVariant.TEXT],
    )
