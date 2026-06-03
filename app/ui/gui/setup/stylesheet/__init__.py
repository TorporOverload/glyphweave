"""Application QSS builder."""

from __future__ import annotations

import sys

from ..tokens import TOKENS, ThemeTokens
from . import (
    section_base,
    section_buttons_role,
    section_file_view,
    section_inputs,
    section_misc,
    section_screens,
    section_shell,
)
from .helpers import build_ctx
from .static import ABOUT_MODAL_QSS, WINDOWS_MENUBAR_QSS


def build_stylesheet(tokens: ThemeTokens = TOKENS) -> str:
    """Concatenate every section's QSS chunk into one string.

    Order: base styles first, then screens/modals, then per-role
    button overrides, fields/lists/sidebar, file-view chrome, and finally
    the badges/alerts/tabs section that wins over earlier rules."""
    
    ctx = build_ctx(tokens)
    parts = [
        section_base.build(ctx),
        section_screens.build(ctx),
        section_buttons_role.build(ctx),
        section_inputs.build(ctx),
        section_file_view.build(ctx),
        section_misc.build(ctx),
        # section_shell appended LAST so its objectName selectors override
        # the broader role-based rules above. See section_shell.py.
        section_shell.build(ctx),
    ]
    css = "".join(parts)
    if sys.platform == "win32":
        css += WINDOWS_MENUBAR_QSS
    css += ABOUT_MODAL_QSS
    return css


__all__ = ["build_stylesheet"]
