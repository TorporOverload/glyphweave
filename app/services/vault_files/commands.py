from __future__ import annotations

from pathlib import Path

from .helpers import (
    collapse_descendant_entries,
    ensure_no_nested_selection,
    is_descendant_path,
)
from .vault_file_import import add_file as add_file_to_vault


def add_file(
    service,
    source,
    dest_name: str | None = None,
    dest_parent_virtual_path: str | None = None,
):
    return add_file_to_vault(
        service.context,
        file_service=service._require_file_service(),
        folder_service=service._require_folder_service(),
        encryption_service=service._require_encryption_service(),
        indexing_service=service._build_indexing_service(),
        event_emitter=service._build_event_emitter(),
        source=source,
        dest_name=dest_name,
        dest_parent_virtual_path=dest_parent_virtual_path,
    )


def copy_entry(
    service,
    source_virtual_path: str,
    destination_folder_virtual_path: str = "/",
    new_name: str | None = None,
):
    source = service._get_entry_by_virtual_path(source_virtual_path)
    if source is None:
        raise FileNotFoundError(f"Vault entry not found: {source_virtual_path}")

    destination_parent_id = service._resolve_or_create_destination_parent_id(
        destination_folder_virtual_path
    )
    if source.is_folder and is_descendant_path(
        destination_folder_virtual_path,
        source.virtual_path,
    ):
        raise ValueError("Cannot copy a folder into itself or its descendant")

    return _copy_reference(
        service,
        source.id,
        destination_parent_id,
        new_name=new_name,
    )


def move_entries(
    service,
    source_virtual_paths: list[str],
    destination_folder_virtual_path: str = "/",
):
    if not source_virtual_paths:
        return []

    entries = service._resolve_entries(source_virtual_paths)
    ensure_no_nested_selection(entries)
    destination_parent_id = service._resolve_or_create_destination_parent_id(
        destination_folder_virtual_path
    )

    names = [entry.name for entry in entries]
    if len(set(names)) != len(names):
        raise ValueError(
            "Cannot move multiple entries with the same name "
            "into one destination folder"
        )

    folder_service = service._require_folder_service()
    moving_ids = {entry.id for entry in entries}
    for entry in entries:
        existing = folder_service.get_child_by_name(destination_parent_id, entry.name)
        if existing is not None and existing.id not in moving_ids:
            raise FileExistsError(
                f"An entry named '{entry.name}' already exists in the destination"
            )

    moved = []
    for entry in entries:
        if entry.is_folder and is_descendant_path(
            destination_folder_virtual_path,
            entry.virtual_path,
        ):
            raise ValueError("Cannot move a folder into itself or its descendant")
        folder_service.rename_entry(entry.id, entry.name, destination_parent_id)
        updated_entry = service._get_entry_by_id(entry.id)
        service._emit_move_event(updated_entry, destination_parent_id, entry.name)
        moved.append(updated_entry)
    return moved


def delete_entries(service, source_virtual_paths: list[str]) -> int:
    if not source_virtual_paths:
        return 0

    entries = service._resolve_entries(source_virtual_paths)
    entries = collapse_descendant_entries(entries)
    folder_service = service._require_folder_service()
    event_emitter = service._build_event_emitter()
    orphan_ids: list[int] = []
    for entry in entries:
        if event_emitter is not None:
            service._emit_delete_event(entry)
        orphan_ids.extend(folder_service.delete_entry(entry.id))
    folder_service.gc.cleanup_batch(orphan_ids)
    return len(entries)


def rename_entry(service, source_virtual_path: str, new_name: str):
    source = service._get_entry_by_virtual_path(source_virtual_path)
    if source is None:
        raise FileNotFoundError(f"Vault entry not found: {source_virtual_path}")

    service._require_folder_service().rename_entry(
        source.id, new_name, source.parent_id
    )
    updated_entry = service._get_entry_by_id(source.id)
    service._emit_move_event(updated_entry, source.parent_id, new_name)
    return updated_entry


def export_entries(
    service,
    source_virtual_paths: list[str],
    destination_dir: Path,
) -> list[Path]:
    if not source_virtual_paths:
        return []

    entries = service._resolve_entries(source_virtual_paths)
    ensure_no_nested_selection(entries)

    destination_root = Path(destination_dir)
    destination_root.mkdir(parents=True, exist_ok=True)
    exported: list[Path] = []
    for entry in entries:
        exported.append(_export_reference(service, entry.id, destination_root))
    return exported


def _copy_reference(
    service,
    source_ref_id: int,
    destination_parent_id: int | None,
    *,
    new_name: str | None = None,
):
    source = service._get_entry_by_id(source_ref_id)
    target_name = new_name or source.name
    if source.is_folder:
        created_folder = service._require_folder_service().create_folder(
            target_name,
            destination_parent_id,
        )
        event_emitter = service._build_event_emitter()
        if event_emitter is not None:
            event_emitter.emit_folder_create(created_folder)
        for child in service._require_folder_service().get_children(source.id):
            _copy_reference(service, child.id, created_folder.id)
        return created_folder

    if source.file_entry_id is None:
        raise RuntimeError(f"File reference {source.id} has no file entry")
    created_ref = service._require_file_service().create_file_reference(
        name=target_name,
        parent_id=destination_parent_id,
        file_entry_id=source.file_entry_id,
    )
    event_emitter = service._build_event_emitter()
    if event_emitter is not None:
        event_emitter.emit_file_add(created_ref)
    return created_ref


def _export_reference(
    service,
    source_ref_id: int,
    destination_parent: Path,
    *,
    override_name: str | None = None,
) -> Path:
    source = service._get_entry_by_id(source_ref_id)
    target_path = destination_parent / (override_name or source.name)
    if target_path.exists():
        raise FileExistsError(f"Export destination already exists: {target_path}")
    if source.is_folder:
        target_path.mkdir(parents=True, exist_ok=False)
        for child in service._require_folder_service().get_children(source.id):
            _export_reference(service, child.id, target_path)
        return target_path

    file_ref = service._require_file_service().get_file_reference_with_blobs(source.id)
    if file_ref is None or file_ref.file_entry is None:
        raise FileNotFoundError(f"Vault file not found: {source.virtual_path}")

    vault_path = service.context.require_vault_path()
    vault_id = service.context.require_vault_id().encode("utf-8")
    master_key = service.context.require_master_key().view()
    blob_ids = [blob.blob_id for blob in file_ref.file_entry.blobs]
    target_path.parent.mkdir(parents=True, exist_ok=True)
    service._require_encryption_service().decrypt_file(
        vault_path=vault_path,
        blob_ids=blob_ids,
        output_path=target_path,
        master_key=master_key,
        vault_id=vault_id,
        file_id=file_ref.file_entry.file_id,
    )
    return target_path
