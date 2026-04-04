from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.common.logging import logger

SUPPORTED_EXTENSIONS = frozenset(
    {
        ".txt",
        ".md",
        ".tex",
        ".pdf",
        ".docx",
        ".doc",
        ".xlsx",
        ".xls",
        ".pptx",
        ".ppt",
    }
)
PREVIEW_MAX_LENGTH = 500


@dataclass
class ExtractionResult:
    content: str = ""
    preview: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    unsupported: bool = False


def _run_kreuzberg_extraction(file_path: Path) -> tuple[str, dict[str, Any]]:
    from kreuzberg import ExtractionConfig, extract_file_sync

    result = extract_file_sync(str(file_path), config=ExtractionConfig())
    content = result.content or ""
    metadata = result.metadata or {}
    return content, metadata


def _is_unsupported_parse_error(file_path: Path, error_text: str) -> bool:
    suffix = file_path.suffix.lower()
    normalized = error_text.lower()
    if suffix == ".pdf":
        return (
            "invalid pdf" in normalized
            or "pdf is password-protected" in normalized
            or "pdfiumlibraryinternalerror: formaterror" in normalized
        )
    if suffix in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}:
        return (
            "password-protected" in normalized
            or "password protected" in normalized
            or "encrypted" in normalized
        )
    return False


class ExtractionService:
    @staticmethod
    def is_supported(filename: str) -> bool:
        return Path(filename).suffix.lower() in SUPPORTED_EXTENSIONS

    @staticmethod
    def extract(file_path: Path) -> ExtractionResult:
        path = Path(file_path)
        if not path.exists():
            return ExtractionResult(error=f"File not found: {path}")
        if not path.is_file():
            return ExtractionResult(error=f"Path is not a file: {path}")
        if not ExtractionService.is_supported(path.name):
            return ExtractionResult(error=f"Unsupported format: {path.suffix.lower()}")

        try:
            logger.info(f"Extraction started: {path.name}")
            content, metadata = _run_kreuzberg_extraction(path)
            logger.info(
                f"Extraction completed: {path.name} "
                f"(chars={len(content)}, metadata_keys={len(metadata)})"
            )
            return ExtractionResult(
                content=content,
                preview=content[:PREVIEW_MAX_LENGTH],
                metadata=metadata,
            )
        except Exception as exc:
            logger.warning(f"Text extraction failed for {path.name}: {exc}")
            error_text = str(exc)
            return ExtractionResult(
                error=error_text,
                unsupported=_is_unsupported_parse_error(path, error_text),
            )
