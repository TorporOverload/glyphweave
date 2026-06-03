from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import QLabel, QWidget

_ICONS_DIR = Path(__file__).resolve().parent.parent / "assets" / "icons" / "ph-icons"


def ph_icon_path(name: str) -> Path:
    """Return the absolute path to a Phosphor icon SVG.

    ``name`` may be either ``"folder-open"`` or ``"folder-open.svg"`` -
    the ``.svg`` suffix is added if missing. Callers do not need to know
    about the legacy ``PH_ICON_MAP`` indirection any more.
    """
    if not name.endswith(".svg"):
        name = f"{name}.svg"
    return _ICONS_DIR / name

# Cache to memoize the tinted icon results by (name, size, color)
# to avoid redundant icon loading and painting operations.
_TINTED_ICON_CACHE: dict[tuple[str, int, int], QIcon] = {}


def tinted_icon(
    name: str,
    *,
    size: int = 18,
    color: QColor | None = None,
) -> QIcon:
    """Load a Phosphor icon by ``name`` and tint it with ``color``.

    The icon must exist as ``<name>.svg`` under ``assets/icons/ph-icons/``.
    Missing files produce an empty ``QIcon`` (logged below) rather than an
    exception so a typo doesn't crash the GUI.

    Results are cached by (name, size, color) - see ``_TINTED_ICON_CACHE``.
    """
    effective_color = color or QColor("#5e81ac")
    cache_key = (name, size, effective_color.rgba())
    cached = _TINTED_ICON_CACHE.get(cache_key)
    if cached is not None:
        return cached

    from PySide6.QtSvg import QSvgRenderer

    path = ph_icon_path(name)
    renderer = QSvgRenderer(str(path))
    if not renderer.isValid():
        # Surface the missing file in the log so it doesn't fail silently -
        # the previous behavior of returning an empty QIcon was the source
        # of the "icon doesn't render" class of bugs across the redesign.
        try:
            from app.common.logging import logger

            logger.warning("tinted_icon: missing or invalid SVG: %s", path)
        except Exception:
            raise
        return QIcon()

    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)
    painter = QPainter(px)
    renderer.render(painter)
    painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
    painter.fillRect(px.rect(), effective_color)
    painter.end()
    icon = QIcon(px)
    _TINTED_ICON_CACHE[cache_key] = icon
    return icon


class IconLabel(QLabel):
    """A fixed-size QLabel that displays a tinted Phosphor icon.
        Used for static icons """

    def __init__(
        self,
        icon_name: str,
        *,
        size: int = 16,
        color: QColor | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.setPixmap(
            tinted_icon(icon_name, size=size, color=color).pixmap(size, size)
        )