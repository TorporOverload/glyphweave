"""Atomic file writing helpers."""

from __future__ import annotations

import os
import tempfile
import time
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
        _replace_with_retry(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _replace_with_retry(
    src: str, dst: Path, retries: int = 5, delay: float = 0.05
) -> None:
    """Retry os.replace on PermissionError.

    On Windows, AV scanners or concurrent readers can briefly hold the
    destination file open, causing os.replace to fail with WinError 5.
    """
    for attempt in range(retries):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == retries - 1:
                raise
            time.sleep(delay)
