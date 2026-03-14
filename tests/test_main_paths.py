from pathlib import Path

import pytest

from app.cli import VaultCLI
from app.utils.file_extensions import ensure_extension_from_mime


def test_safe_cache_path_strips_traversal_segments(tmp_path: Path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    safe_path = VaultCLI._safe_cache_path(cache_dir, "../outside.txt")

    assert safe_path.parent == cache_dir.resolve()
    assert safe_path.name == "outside.txt"


def test_safe_cache_path_rejects_invalid_names(tmp_path: Path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    with pytest.raises(ValueError, match="Invalid vault filename"):
        VaultCLI._safe_cache_path(cache_dir, "..")


def test_ensure_extension_from_mime_keeps_existing_extension():
    result = ensure_extension_from_mime("report.txt", "text/plain")
    assert result == "report.txt"


def test_ensure_extension_from_mime_adds_extension_when_missing():
    result = ensure_extension_from_mime(
        "report",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    assert result == "report.docx"
