import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app.common.atomic_write import atomic_write_bytes, atomic_write_text


class TestAtomicWriteText:
    def test_writes_utf8_content(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"
        atomic_write_text(target, "Hello, GlyphWeave!")

        assert target.read_text(encoding="utf-8") == "Hello, GlyphWeave!"

    def test_writes_with_custom_encoding(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"
        atomic_write_text(target, "こんにちは", encoding="utf-8")

        assert target.read_text(encoding="utf-8") == "こんにちは"

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        target = tmp_path / "subdir" / "nested" / "test.txt"
        assert not target.parent.exists()

        atomic_write_text(target, "content")

        assert target.exists()
        assert target.read_text() == "content"

    def test_overwrites_existing_file(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"
        target.write_text("original")
        atomic_write_text(target, "replaced")

        assert target.read_text() == "replaced"


class TestAtomicWriteBytes:
    def test_writes_raw_bytes(self, tmp_path: Path) -> None:
        target = tmp_path / "test.bin"
        data = bytes(range(256))
        atomic_write_bytes(target, data)

        assert target.read_bytes() == data

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        target = tmp_path / "subdir" / "test.bin"
        assert not target.parent.exists()

        atomic_write_bytes(target, b"binary data")

        assert target.exists()

    def test_overwrites_existing_file(self, tmp_path: Path) -> None:
        target = tmp_path / "test.bin"
        target.write_bytes(b"original")
        atomic_write_bytes(target, b"replaced")

        assert target.read_bytes() == b"replaced"


class TestAtomicWriteFailureCleanup:
    def test_removes_temp_file_on_write_failure(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"

        with patch("os.fdopen") as mock_fdopen:
            mock_fdopen.side_effect = OSError("Simulated write failure")

            with pytest.raises(OSError):
                atomic_write_text(target, "content")

    def test_simulated_failure_cleanup(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"

        with patch("os.fsync") as mock_fsync:
            mock_fsync.side_effect = OSError("Sync failed")

            with pytest.raises(OSError):
                atomic_write_text(target, "content")
