"""Atomic file writing helpers."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write_text(path: Path, content: str, encoding: str = "utf-8") -> None:
    """Atomically write text content to ``path``."""
    _atomic_write(path, mode="w", data=content, encoding=encoding)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Atomically write bytes to ``path``."""
    _atomic_write(path, mode="wb", data=data)


def _atomic_write(
    path: Path,
    *,
    mode: str,
    data: str | bytes,
    encoding: str | None = None,
) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=parent, suffix=".tmp")
    try:
        with os.fdopen(fd, mode, encoding=encoding) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
