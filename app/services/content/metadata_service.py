from __future__ import annotations

import mimetypes
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.services.content.extraction_service import ExtractionService


@dataclass
class FileMetadataResult:
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class FileMetadataService:
    @staticmethod
    def _created_timestamp(stat_result: Any) -> float:
        """Prefer filesystem birth time when available, with a portable fallback."""
        return float(getattr(stat_result, "st_birthtime", stat_result.st_ctime))

    @staticmethod
    def extract(file_path: Path) -> FileMetadataResult:
        path = Path(file_path)
        if not path.exists():
            return FileMetadataResult(error=f"File not found: {path}")
        if not path.is_file():
            return FileMetadataResult(error=f"Path is not a file: {path}")

        stat_result = path.stat()
        mime_type, _ = mimetypes.guess_type(path.name)
        metadata = {
            "file_name": path.name,
            "extension": path.suffix.lower(),
            "mime_type": mime_type or "application/octet-stream",
            "size_bytes": stat_result.st_size,
            "created_at": datetime.fromtimestamp(
                FileMetadataService._created_timestamp(stat_result), tz=timezone.utc
            ).isoformat(),
            "modified_at": datetime.fromtimestamp(
                stat_result.st_mtime, tz=timezone.utc
            ).isoformat(),
            "text_extraction_supported": ExtractionService.is_supported(path.name),
        }
        return FileMetadataResult(metadata=metadata)

