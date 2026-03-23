from pathlib import Path

from app.services.content.metadata_service import FileMetadataService


def test_extract_returns_basic_metadata_for_supported_file(tmp_path: Path) -> None:
    file_path = tmp_path / "hello.txt"
    file_path.write_text("Hello, world!", encoding="utf-8")

    result = FileMetadataService.extract(file_path)

    assert result.error is None
    assert result.metadata["file_name"] == "hello.txt"
    assert result.metadata["extension"] == ".txt"
    assert result.metadata["mime_type"] == "text/plain"
    assert result.metadata["size_bytes"] == len("Hello, world!")
    assert result.metadata["text_extraction_supported"] is True
    assert "created_at" in result.metadata
    assert "modified_at" in result.metadata


def test_extract_returns_basic_metadata_for_unsupported_file(tmp_path: Path) -> None:
    file_path = tmp_path / "photo.png"
    file_path.write_bytes(b"\x89PNG\r\n")

    result = FileMetadataService.extract(file_path)

    assert result.error is None
    assert result.metadata["file_name"] == "photo.png"
    assert result.metadata["extension"] == ".png"
    assert result.metadata["mime_type"] == "image/png"
    assert result.metadata["size_bytes"] == 6
    assert result.metadata["text_extraction_supported"] is False
