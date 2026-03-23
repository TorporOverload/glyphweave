import mimetypes
from pathlib import Path

_MIME_EXTENSION_OVERRIDES = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    ): ".pptx",
    "application/msword": ".doc",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.ms-powerpoint": ".ppt",
}


def extension_from_mime(mime_type: str | None) -> str | None:
    """Return the preferred file extension for the given MIME type, or None if
    unknown."""
    if not mime_type:
        return None

    lowered = mime_type.lower().strip()
    if lowered in _MIME_EXTENSION_OVERRIDES:
        return _MIME_EXTENSION_OVERRIDES[lowered]

    ext = mimetypes.guess_extension(lowered, strict=False)
    return ext


def ensure_extension_from_mime(
    file_name: str,
    mime_type: str | None,
    default_extension: str = ".bin",
) -> str:
    """Return the filename with an extension appended from the MIME type if none is
    already present."""
    base_name = Path(str(file_name)).name or "file"
    if Path(base_name).suffix:
        return base_name

    extension = extension_from_mime(mime_type) or default_extension
    if not extension.startswith("."):
        extension = f".{extension}"
    return f"{base_name}{extension}"
