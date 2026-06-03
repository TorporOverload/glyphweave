"""Shared formatting helpers for the conflict resolution dialog."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def format_datetime(value: Any) -> str:
    """Render a datetime as ``YYYY-MM-DD HH:MM:SS UTC``."""
    if not isinstance(value, datetime):
        return str(value) if value else "unknown"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def format_relative(value: Any) -> str:
    """Render a datetime as a coarse relative label (e.g. ``2h ago``)."""
    if not isinstance(value, datetime):
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    delta = now - value
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    if seconds < 604800:
        return f"{seconds // 86400}d ago"
    return value.strftime("%Y-%m-%d")


def format_short_date(value: Any) -> str:
    """Compact date label for list-rail rows: ``MM-DD HH:MMZ``."""
    if not isinstance(value, datetime):
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%m-%d %H:%MZ")


def keep_both_suffix(now: datetime | None = None) -> str:
    """The ``(conflict - dd-mm-yyyy-hh-ss)`` suffix used by the Keep-both action.

    The format intentionally avoids characters that need quoting in shells
    or file pickers (no colons, no slashes).
    """
    when = now or datetime.now(timezone.utc)
    return f"(conflict - {when.strftime('%d-%m-%Y-%H-%S')})"


def keep_both_filename(original_name: str, now: datetime | None = None) -> str:
    """Compose the ``Keep both`` filename: ``stem (conflict - …).ext``."""
    suffix = keep_both_suffix(now)
    if "." in original_name:
        stem, _, ext = original_name.rpartition(".")
        return f"{stem} {suffix}.{ext}"
    return f"{original_name} {suffix}"


def parent_path(virtual_path: str | None) -> str:
    """Return the parent directory of a virtual path, normalized to ``/``."""
    if not virtual_path or virtual_path == "/":
        return "/"
    parts = virtual_path.rstrip("/").split("/")
    if len(parts) <= 2:
        return "/"
    return "/".join(parts[:-1]) or "/"


_CONFLICT_PREFIX = "/.glyphweave_conflicts"


def original_parent_path(archived_virtual_path: str | None) -> str:
    """Strip ``/.glyphweave_conflicts`` to derive the file's pre-conflict parent.

    Returns ``"/"`` when the input is missing or doesn't sit under the
    conflicts archive.
    """
    if not archived_virtual_path:
        return "/"
    if not archived_virtual_path.startswith(_CONFLICT_PREFIX):
        return parent_path(archived_virtual_path)
    rest = archived_virtual_path[len(_CONFLICT_PREFIX):]
    if not rest.startswith("/"):
        rest = "/" + rest
    return parent_path(rest)
