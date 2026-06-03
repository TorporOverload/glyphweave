"""Data classes used by the file-view package."""

from __future__ import annotations

from dataclasses import dataclass


# Qt user-data role index used by FileViewScreen tree items to carry the
# vault-internal virtual path.
_TREE_PATH_ROLE = 256


@dataclass(frozen=True, slots=True)
class FileEntry:
    file_ref_id: int | None
    name: str
    type_label: str
    modified: str
    status: str
    indexed: bool
    accent: str
    icon_name: str
    path: str
    parent_path: str
    is_folder: bool = False
    property_rows: tuple[tuple[str, str], ...] = ()
    preview_text: str = "no content preview available"


@dataclass(frozen=True, slots=True)
class UnlockedFile:
    file_ref_id: int
    name: str
    path: str = ""
    display_path: str = ""
