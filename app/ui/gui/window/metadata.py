"""Metadata mapping helpers"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from app.infrastructure.persistence.db.model.extraction_status import ExtractionStatus

from .. import gui_utils
from ..gui_utils import FileViewPayload
from ..screens import VaultListEntry
from ..screens.file_view import FileEntry, UnlockedFile

if TYPE_CHECKING:
    from ..glyphweave_ui import GlypheaveGUI

# Vault-list entries

def load_vault_entries(window: "GlypheaveGUI") -> list[VaultListEntry]:
    known = window.service.load_known_vaults()
    entries: list[VaultListEntry] = []
    for index, vault in enumerate(known):
        entries.append(
            VaultListEntry(
                vault_id=str(vault.get("vault_id", "")),
                name=str(
                    vault.get("vault_alias")
                    or vault.get("path")
                    or "Unknown vault"
                ),
                path=str(vault.get("path", "")),
                last_opened=gui_utils.format_last_opened(vault.get("last_opened")),
                highlighted=index == 0,
            )
        )
    return entries


# File view payload

_CONFLICT_FOLDER_PATH = "/.glyphweave_conflicts"


def _is_conflict_entry(virtual_path: str) -> bool:
    """True for the conflicts folder itself or anything nested inside it.

    The conflicts folder is an internal sync-resolution artefact owned by
    :mod:`app.services.vault_integrity_service`; users interact with
    conflicts through the bell/notification UI, not by browsing this
    folder directly, so it must not appear in the tree or file table.
    """
    if not isinstance(virtual_path, str):
        return False
    return (
        virtual_path == _CONFLICT_FOLDER_PATH
        or virtual_path.startswith(f"{_CONFLICT_FOLDER_PATH}/")
    )


def build_file_view_payload(
    window: "GlypheaveGUI",
) -> FileViewPayload:
    vault_name = window.service.vault_name or "glyphweave"
    references = [
        ref
        for ref in window.service.list_all_entries()
        if not _is_conflict_entry(getattr(ref, "virtual_path", ""))
    ]
    ref_by_id = {ref.id: ref for ref in references}
    unlocked_items = window.service.list_unlocked_files()
    return FileViewPayload(
        vault_name=vault_name,
        entries=[map_reference(window, ref) for ref in references],
        unlocked_files=[
            UnlockedFile(
                file_ref_id=item.file_ref_id,
                name=item.file_name,
                path=ref_by_id[item.file_ref_id].virtual_path,
                display_path=display_unlocked_path(
                    vault_name, ref_by_id[item.file_ref_id].virtual_path
                ),
            )
            for item in unlocked_items
            if item.file_ref_id in ref_by_id
        ],
    )


def display_unlocked_path(vault_name: str, virtual_path: str) -> str:
    normalized = (
        virtual_path if virtual_path.startswith("/") else f"/{virtual_path}"
    )
    return f"/{vault_name}{normalized}"


# Reference → FileEntry

def map_reference(window: "GlypheaveGUI", ref) -> FileEntry:
    parent_path = gui_utils.parent_path(ref.virtual_path)
    file_entry = getattr(ref, "file_entry", None)
    metadata = gui_utils.parse_metadata_json(
        getattr(file_entry, "metadata_json", None)
    )
    if ref.is_folder:
        return FileEntry(
            file_ref_id=ref.id,
            name=ref.name,
            type_label="Folder",
            modified=gui_utils.format_datetime(getattr(ref, "modified_at", None)),
            status="",
            indexed=False,
            accent="#d08770",
            icon_name="folder",
            path=ref.virtual_path,
            parent_path=parent_path,
            is_folder=True,
            property_rows=(
                ("Type", "Folder"),
                ("Path", _display_vault_path(window, ref.virtual_path)),
                (
                    "Modified",
                    gui_utils.format_datetime_full(
                        getattr(ref, "modified_at", None)
                    ),
                ),
            ),
            preview_text="no content preview available",
        )

    status_key = getattr(
        file_entry, "text_extraction_status", ExtractionStatus.PENDING.value
    )
    status = {
        ExtractionStatus.DONE.value: "indexed",
        ExtractionStatus.PENDING.value: "pending",
        ExtractionStatus.FAILED.value: "index failed",
        ExtractionStatus.UNSUPPORTED.value: "unsupported",
    }.get(status_key, status_key)
    indexed = status_key == ExtractionStatus.DONE.value
    icon_name, accent = gui_utils.file_icon_spec(ref.name)
    return FileEntry(
        file_ref_id=ref.id,
        name=ref.name,
        type_label=gui_utils.extension_label(ref.name),
        modified=gui_utils.format_datetime(getattr(ref, "modified_at", None)),
        status=status,
        indexed=indexed,
        accent=accent,
        icon_name=icon_name,
        path=ref.virtual_path,
        parent_path=parent_path,
        is_folder=False,
        property_rows=build_property_rows(window, ref, metadata),
        preview_text=getattr(file_entry, "extracted_text_preview", None)
        or "no content preview available",
    )


# Property rows (right inspector)

def build_property_rows(
    window: "GlypheaveGUI", ref, metadata: dict[str, object]
) -> tuple[tuple[str, str], ...]:
    rows: list[tuple[str, str]] = []
    consumed: set[str] = set()

    author = gui_utils.metadata_first(
        metadata,
        "author",
        "creator",
        "owner",
        formatter=gui_utils.format_metadata_value,
    )
    if author:
        rows.append(("Author", author))
        consumed.update({"author", "creator", "owner"})

    rows.append(("Type", _build_type_label(ref, metadata)))

    size_value = gui_utils.metadata_size(
        metadata,
        getattr(getattr(ref, "file_entry", None), "original_size_bytes", None),
    )
    if size_value:
        rows.append(("Size", size_value))
        consumed.add("size_bytes")

    created_value = gui_utils.metadata_datetime(
        metadata,
        ("created_at", "created"),
        fallback=getattr(getattr(ref, "file_entry", None), "created_at", None),
    )
    if created_value:
        rows.append(("Created", created_value))
        consumed.update({"created_at", "created"})

    modified_value = gui_utils.metadata_datetime(
        metadata,
        ("modified_at", "updated_at"),
        fallback=getattr(ref, "modified_at", None),
    )
    if modified_value:
        rows.append(("Modified", modified_value))
        consumed.update({"modified_at", "updated_at"})

    rows.append(("Path", _display_vault_path(window, ref.virtual_path)))
    rows.append(("Security", "AES-256 E2E"))

    # Office files (.docx/.xlsx/.pptx) have three nested-dict metadata
    # buckets - `core_properties`, `app_properties`, `custom_properties`.
    # Flatten one level so each entry becomes its own row instead of
    # dumping the dict's repr() as a single unreadable string.
    seen_labels = {label.lower() for label, _ in rows}
    skip_keys = {"file_name", "extension", "mime_type"}

    def emit_pair(sub_key: str, sub_val: object) -> None:
        if sub_key in skip_keys:
            return
        formatted = gui_utils.format_metadata_value(sub_val)
        if not formatted:
            return
        label = gui_utils.labelize_metadata_key(sub_key)
        if label.lower() in seen_labels:
            return
        rows.append((label, formatted))
        seen_labels.add(label.lower())

    for key in sorted(metadata):
        if key in consumed:
            continue
        raw = metadata[key]
        if isinstance(raw, dict):
            for sub_key in sorted(raw):
                emit_pair(sub_key, raw[sub_key])
        else:
            emit_pair(key, raw)
    return tuple(rows)

# Import-job expansion

def expand_import_jobs(
    import_paths: list[str],
    destination_folder_virtual_path: str,
) -> list[tuple[Path, str]]:
    base_destination = destination_folder_virtual_path or "/"
    jobs: list[tuple[Path, str]] = []
    for raw_path in import_paths:
        source = Path(raw_path)
        if source.is_file():
            jobs.append((source, base_destination))
            continue
        if not source.is_dir():
            continue
        for nested in source.rglob("*"):
            if not nested.is_file():
                continue
            relative_parent = nested.relative_to(source).parent
            target_parent = base_destination.rstrip("/")
            target_parent = target_parent if target_parent else "/"
            if str(relative_parent) != ".":
                joined = "/".join(relative_parent.parts)
                target_parent = (
                    f"{target_parent}/{source.name}/{joined}".replace("//", "/")
                    if target_parent != "/"
                    else f"/{source.name}/{joined}"
                )
            else:
                target_parent = (
                    f"{target_parent}/{source.name}".replace("//", "/")
                    if target_parent != "/"
                    else f"/{source.name}"
                )
            jobs.append((nested, target_parent))
    return jobs

# Internal helpers


def _build_type_label(ref, metadata: dict[str, object]) -> str:
    mime_type = gui_utils.metadata_first(
        metadata, "mime_type", formatter=gui_utils.format_metadata_value
    ) or getattr(getattr(ref, "file_entry", None), "mime_type", "")
    return gui_utils.build_type_label(ref.name, metadata, mime_type or "")


def _display_vault_path(window: "GlypheaveGUI", virtual_path: str) -> str:
    return gui_utils.display_vault_path(
        virtual_path, window.service.vault_name or "glyphweave"
    )
