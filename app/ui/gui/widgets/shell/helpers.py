"""Shared helpers for the ``shell`` widget package."""

from __future__ import annotations

from PySide6.QtGui import QColor


def css_color(color: QColor) -> str:
    """Render a QColor as a Qt-stylesheet-friendly colour string."""
    if color.alpha() == 255:
        return color.name()
    alpha = color.alpha() / 255
    return f"rgba({color.red()}, {color.green()}, {color.blue()}, {alpha:.3f})"
