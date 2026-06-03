from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import QWidget

from app.common.logging import logger
from app.ui.gui.setup.types import FILE_ICON_MAP

_MONTH_ABBR = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)


def _safe_local(dt: datetime) -> datetime:
    try:
        return dt.astimezone()
    except (OSError, OverflowError, ValueError):
        return dt


class TaskThread(QThread):
    """Lightweight QThread wrapper that runs a callable in the background
    and emits ``succeeded`` with the result or ``failed`` with an error
    string. Workers that want to report progress can emit on the parent
    window's progress signals directly."""

    succeeded = Signal(object)
    failed = Signal(str)
    progress = Signal(int, int, str)  # current, total, label

    def __init__(
        self,
        fn: Callable[[], object],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:
        try:
            result = self._fn()
        except Exception as exc:
            logger.exception("Background task failed: %s", exc)
            self.failed.emit(str(exc))
            return
        self.succeeded.emit(result)


@dataclass(frozen=True, slots=True)
class CreatedVaultResult:
    vault_id: str
    recovery_words: list[str]


@dataclass(frozen=True, slots=True)
class PreparedVaultResult:
    vault_id: str
    name: str
    path: str


@dataclass(frozen=True, slots=True)
class FileViewPayload:
    vault_name: str
    entries: list
    unlocked_files: list


def parent_path(virtual_path: str) -> str:
    """Return the parent path of a virtual vault path."""
    stripped = virtual_path.strip("/")
    if not stripped or "/" not in stripped:
        return "/"
    return "/" + stripped.rsplit("/", 1)[0]


def extension_label(name: str) -> str:
    """Return a short uppercase label for a file's extension."""
    suffix = Path(name).suffix.lower().lstrip(".")
    return suffix.upper() if suffix else "FILE"


def file_icon_spec(name: str) -> tuple[str, str]:
    """
    Return a (icon-key, hex-color) pair for the given filename.

    Mirrors the mapping in file_view.py and search_screen.py so it can be used
    without importing either screen.
    """
    suffix = Path(name).suffix.lower()
    return FILE_ICON_MAP.get(suffix, ("file-text", "#5e81ac"))


def parse_metadata_json(value: object) -> dict[str, object]:
    """Parse a JSON string stored in vault metadata."""
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def metadata_first(
    metadata: dict[str, object],
    *keys: str,
    formatter: Callable[[object], str] | None = None,
) -> str:
    """
    Return the first non-empty value among ``keys`` in ``metadata``.

    If ``formatter`` is supplied it is called with the raw value before the
    empty check (to apply ``format_metadata_value``).
    """
    for key in keys:
        value = metadata.get(key)
        if value is None:
            continue
        text = formatter(value) if formatter else str(value) if value else ""
        if text:
            return text
    return ""


def metadata_size(metadata: dict[str, object], fallback: object) -> str:
    """Return a human-readable size string from metadata."""
    value = metadata.get("size_bytes", fallback)
    try:
        size_bytes = int(str(value)) if value is not None else None
    except (TypeError, ValueError):
        return ""
    if size_bytes is None:
        return ""
    return format_size(size_bytes)


def metadata_datetime(
    metadata: dict[str, object],
    keys: tuple[str, ...],
    *,
    fallback: object = None,
) -> str:
    """Return a formatted datetime string from the first matching key in metadata."""
    for key in keys:
        if key not in metadata:
            continue
        formatted = format_datetime_full(metadata.get(key))
        if formatted:
            return formatted
    return format_datetime_full(fallback)

def labelize_metadata_key(key: str) -> str:
    """Convert a snake_case key to a Title Case label."""
    return key.replace("_", " ").strip().title()


def format_metadata_value(value: object) -> str:
    """Format a raw metadata value for display."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item is not None)
    if isinstance(value, dict):
        # Caller is responsible for flattening dicts into individual rows.
        # Returning the raw repr would dump unreadable strings into the UI.
        return ""
    return str(value)


def format_size(size_bytes: int) -> str:
    """Format a byte count into a human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB ({size_bytes:,} B)"
    return f"{size_bytes / (1024 * 1024):.1f} MB ({size_bytes:,} B)"


def format_last_opened(value: object) -> str:
    """Format an ISO datetime string as a relative time string."""
    if not value:
        return "Never"
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return str(value)
    return format_relative_time(dt)


def format_datetime(value: object) -> str:
    """Format a datetime (or ISO string) as a relative time, or '-' on failure."""
    if not isinstance(value, datetime):
        return "-"
    return format_relative_time(value)


def format_datetime_full(value: object) -> str:
    """
    Format a datetime (or ISO string) as a full local string
    like ``Jan 15, 2025, 03:42 PM``.
    """
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return str(value)
    if not isinstance(value, datetime):
        return ""
    dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    local = _safe_local(dt)
    month = _MONTH_ABBR[local.month - 1]
    hour = local.hour % 12 or 12
    am_pm = "AM" if local.hour < 12 else "PM"
    return (
        f"{month} {local.day}, {local.year}, "
        f"{hour}:{local.minute:02d} {am_pm}"
    )


def format_relative_time(value: datetime) -> str:
    """Return a brief relative-time string (Today / Yesterday / Xd ago / date)."""
    now = datetime.now(timezone.utc)
    dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    delta = now - dt.astimezone(timezone.utc)
    days = delta.days
    if days <= 0:
        return "Today"
    if days == 1:
        return "Yesterday"
    if days < 7:
        return f"{days}d ago"
    local = _safe_local(dt)
    return f"{_MONTH_ABBR[local.month - 1]} {local.day:02d}"


def friendly_extension_name(extension: str) -> str:
    """Return a human-readable description for common file extensions."""
    names = {
        "docx": "Microsoft Word",
        "doc": "Microsoft Word",
        "xlsx": "Microsoft Excel",
        "xls": "Microsoft Excel",
        "csv": "CSV",
        "pdf": "PDF document",
        "md": "Markdown",
        "txt": "Text file",
        "png": "PNG image",
        "jpg": "JPEG image",
        "jpeg": "JPEG image",
        "gif": "GIF image",
        "json": "JSON",
        "py": "Python source",
    }
    return names.get(extension.lower(), extension.upper())


def build_type_label(
    name: str,
    metadata: dict[str, object],
    mime_type: str = "",
) -> str:
    """
    Build a descriptive type label from a filename, its metadata, and
    an optional MIME type (e.g. ``Microsoft Word (.docx)``).
    """
    ext = Path(name).suffix.lower().lstrip(".")
    if ext:
        return f"{friendly_extension_name(ext)} ({ext.upper()})"
    if mime_type:
        return mime_type
    return extension_label(name)


def display_vault_path(
    virtual_path: str,
    vault_name: str = "glyphweave",
) -> str:
    """Return the full display path for a virtual vault path."""
    normalized = virtual_path if virtual_path.startswith("/") else f"/{virtual_path}"
    return f"/{vault_name}{normalized}"
