from pathlib import Path
from PySide6.QtGui import QFontDatabase, QIcon


RESOURCES_DIR = Path(__file__).resolve().parent.parent / "assets",

FONT_SUFFIXES = {".ttf", ".otf", ".woff", ".woff2"}


def load_application_fonts() -> dict[str, list[str]]:
    loaded: dict[str, list[str]] = {}
    for root in RESOURCES_DIR:
        fonts_dir = root / "fonts"
        if not fonts_dir.exists():
            continue
        for path in sorted(fonts_dir.iterdir()):
            if path.is_file() and path.suffix.lower() in FONT_SUFFIXES:
                font_id = QFontDatabase.addApplicationFont(str(path))
                if font_id < 0:
                    continue
                loaded[str(path)] = QFontDatabase.applicationFontFamilies(font_id)
    return loaded


def ph_icon_path(name: str) -> Path:
    return RESOURCES_DIR[0] / "icons" / "ph-icons" / name


def load_app_icon() -> QIcon:
    return QIcon(str(RESOURCES_DIR[0] / "icons" / "glyphweave-icon.png"))


def load_icon(name: str) -> QIcon:
    return QIcon(str(ph_icon_path(name)))

def user_manual_path() -> Path | None:
    """Return the bundled user-manual PDF path, or ``None`` if absent."""
    path = RESOURCES_DIR[0] / "docs" / "gw-user-manual.pdf"
    return path if path.exists() else None


def get_liscence_text(file_name: str | None) -> str | None:
    if file_name is None:
        return (
            "License text not bundled with this build.\n\n"
            "See the project URL above for the upstream license."
        )
    path = RESOURCES_DIR[0] / "oss_liscence" / file_name
    if not path.exists():
        return (
            f"License text not found at {path}.\n\n"
            "See the project URL above for the upstream license."
        )
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"Could not read license file: {exc}"
