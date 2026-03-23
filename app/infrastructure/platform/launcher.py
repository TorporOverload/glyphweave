from __future__ import annotations

import os
import sys
from pathlib import Path


def open_with_default_app(file_path: Path) -> None:
    """Open a file using the operating system's default application."""
    if sys.platform != "win32":
        raise OSError("GlyphWeave currently supports Windows only")

    os.startfile(str(file_path))  # noqa: S606
