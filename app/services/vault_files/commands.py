from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from sqlalchemy import select

from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.model.sync_conflict import SyncConflict
from app.infrastructure.persistence.db.service.session import session_scope
from app.infrastructure.persistence.db.service.sync_conflict_service import (
    get_sync_conflict_by_id,
    resolve_sync_conflict,
)
from app.infrastructure.persistence.db.utils import escape_like_pattern
from app.services.sync.state import local_resolution_event_id 

from .helpers import (
    collapse_descendant_entries,
    ensure_no_nested_selection,
    is_descendant_path,
    normalize_vault_path,
)
from .vault_file_import import add_file as add_file_to_vault

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from app.services.models import AddFileResult
    from app.services.sync.event_emitter import FileRefLike, FolderRefLike
    from app.services.vault_files.vault_file_service import VaultFileService


@dataclass(frozen=True)
class _ConflictResolutionTarget:
    conflict_id: str
    node_id: str
    node_kind: str


def add_file(
    service: "VaultFileService",
    source: Path,
    dest_name: str | None = None,
    dest_parent_virtual_path: str | None = None,
) -> "AddFileResult":
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


def create_folder(
    service: "VaultFileService",
    name: str,
    parent_virtual_path: str = "/",
):
    destination_parent_id = service._resolve_or_create_destination_parent_id(
        parent_virtual_path
    )
    created_folder = service._require_folder_service().create_folder(
        name,
        destination_parent_id,
    )
    event_emitter = service._build_event_emitter()
    if event_emitter is not None:
        event_emitter.emit_folder_create(cast("FolderRefLike", created_folder))
    return created_folder


def copy_entry(
    service: "VaultFileService",
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
    service: "VaultFileService",
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
        if entry.is_folder and is_descendant_path(
            destination_folder_virtual_path,
            entry.virtual_path,
        ):
            raise ValueError("Cannot move a folder into itself or its descendant")
        existing = folder_service.get_child_by_name(destination_parent_id, entry.name)
        if existing is not None and existing.id not in moving_ids:
            raise FileExistsError(
                f"An entry named '{entry.name}' already exists in the destination"
            )

    moved = []
    for entry in entries:
        folder_service.rename_entry(entry.id, entry.name, destination_parent_id)
        updated_entry = service._get_entry_by_id(entry.id)
        service._emit_move_event(updated_entry, destination_parent_id, entry.name)
        moved.append(updated_entry)
    return moved


def delete_entries(service: "VaultFileService", source_virtual_paths: list[str]) -> int:
    if not source_virtual_paths:
        return 0

    entries = service._resolve_entries(source_virtual_paths)
    entries = collapse_descendant_entries(entries)
    folder_service = service._require_folder_service()
    event_emitter = service._build_event_emitter()
    orphan_ids: list[int] = []
    try:
        for entry in entries:
            file_id: str | None = None
            conflicts_to_resolve: list[_ConflictResolutionTarget] = []
            if (
                event_emitter is not None
                and not entry.is_folder
                and entry.file_entry_id is not None
            ):
                hydrated = (
                    service._require_file_service().get_file_reference_with_blobs(
                        entry.id
                    )
                )
                if hydrated is not None and hydrated.file_entry is not None:
                    file_id = hydrated.file_entry.file_id
            session_factory = service.context.session_factory
            if session_factory is not None:
                with session_scope(session_factory, commit=False) as session:
                    conflicts_to_resolve = _list_active_conflicts_for_entry(
                        session, entry
                    )
            orphan_ids.extend(folder_service.delete_entry(entry.id))
            if event_emitter is not None:
                service._emit_delete_event(entry, file_id=file_id)
                resolution_event_ids = _emit_conflict_resolutions(
                    event_emitter,
                    conflicts_to_resolve,
                    resolution_status="deleted",
                    resolution_reason="explicit_delete",
                )
                _resolve_conflicts_locally(
                    session_factory,
                    conflicts_to_resolve,
                    resolution_status="deleted",
                    resolution_event_ids=resolution_event_ids,
                )
            elif session_factory is not None:
                _resolve_conflicts_locally(
                    session_factory,
                    conflicts_to_resolve,
                    resolution_status="deleted",
                )
    finally:
        if orphan_ids:
            folder_service.gc.cleanup_batch(orphan_ids)
    return len(entries)


def rename_entry(service: "VaultFileService", source_virtual_path: str, new_name: str):
    source = service._get_entry_by_virtual_path(source_virtual_path)
    if source is None:
        raise FileNotFoundError(f"Vault entry not found: {source_virtual_path}")

    service._require_folder_service().rename_entry(
        source.id, new_name, source.parent_id
    )
    updated_entry = service._get_entry_by_id(source.id)
    service._emit_move_event(updated_entry, source.parent_id, new_name)
    return updated_entry


def restore_sync_conflict(
    service: "VaultFileService",
    conflict_id: str,
    destination_folder_virtual_path: str = "/",
    new_name: str | None = None,
):
    session_factory = service.context.session_factory
    if session_factory is None:
        raise RuntimeError("Session factory is not initialized")

    normalized_destination = normalize_vault_path(destination_folder_virtual_path)
    with session_scope(session_factory, commit=False) as session:
        conflict = get_sync_conflict_by_id(session, conflict_id)
        if conflict is None:
            raise FileNotFoundError(f"Sync conflict not found: {conflict_id}")
        if conflict.status != "active":
            raise ValueError(f"Sync conflict is not active: {conflict_id}")

        entry = session.scalar(
            select(FileReference).where(FileReference.node_id == conflict.node_id)
        )
        if entry is None:
            raise FileNotFoundError(
                f"Archived conflict entry not found for node: {conflict.node_id}"
            )

        entry_id = entry.id
        is_folder = entry.is_folder
        current_name = entry.name
        current_virtual_path = entry.virtual_path
        conflicts_to_resolve = _list_active_conflicts_for_entry(session, entry)

    if is_folder and is_descendant_path(normalized_destination, current_virtual_path):
        raise ValueError("Cannot restore a folder into itself or its descendant")

    destination_parent_id = service._resolve_or_create_destination_parent_id(
        normalized_destination
    )
    target_name = new_name or current_name
    folder_service = service._require_folder_service()
    existing = folder_service.get_child_by_name(destination_parent_id, target_name)
    if existing is not None and existing.id != entry_id:
        raise FileExistsError(
            f"An entry named '{target_name}' already exists in the destination"
        )

    folder_service.rename_entry(entry_id, target_name, destination_parent_id)
    updated_entry = service._get_entry_by_id(entry_id)
    service._emit_move_event(updated_entry, destination_parent_id, target_name)

    event_emitter = service._build_event_emitter()
    if event_emitter is not None:
        resolution_event_ids = _emit_conflict_resolutions(
            event_emitter,
            conflicts_to_resolve,
            resolution_status="resolved",
            resolution_reason="explicit_restore",
        )
        _resolve_conflicts_locally(
            session_factory,
            conflicts_to_resolve,
            resolution_status="resolved",
            resolution_event_ids=resolution_event_ids,
        )
    else:
        _resolve_conflicts_locally(
            session_factory,
            conflicts_to_resolve,
            resolution_status="resolved",
        )

    return updated_entry


def export_entries(
    service: "VaultFileService",
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
    service: "VaultFileService",
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
            event_emitter.emit_folder_create(cast("FolderRefLike", created_folder))
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
        event_emitter.emit_file_add(cast("FileRefLike", created_ref))
    return created_ref


def _export_reference(
    service: "VaultFileService",
    source_ref_id: int,
    destination_parent: Path,
    *,
    override_name: str | None = None,
) -> Path:
    source = service._get_entry_by_id(source_ref_id)
    target_path = destination_parent / (override_name or source.name)
    if target_path.exists():
        raise FileExistsError(f"Export destination already exists: {target_path}")
    destination_root = destination_parent.resolve()
    target_resolved = target_path.resolve()
    if not target_resolved.is_relative_to(destination_root):
        raise ValueError(
            f"Export target escapes destination directory: {target_path.name}"
        )
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


def _list_active_conflicts_for_entry(
    session: "Session",
    entry: FileReference,
) -> list[_ConflictResolutionTarget]:
    node_ids = [entry.node_id]
    if entry.is_folder:
        escaped_virtual_path = escape_like_pattern(entry.virtual_path)
        node_ids.extend(
            session.scalars(
                select(FileReference.node_id).where(
                    FileReference.virtual_path.like(
                        escaped_virtual_path + "/%",
                        escape="\\",
                    )
                )
            ).all()
        )

    conflicts = session.scalars(
        select(SyncConflict).where(
            SyncConflict.status == "active",
            SyncConflict.node_id.in_(node_ids),
        )
    ).all()
    ordered = sorted(
        conflicts,
        key=lambda item: (
            item.archived_virtual_path or "",
            item.node_id,
            item.conflict_id,
        ),
    )
    return [
        _ConflictResolutionTarget(
            conflict_id=conflict.conflict_id,
            node_id=conflict.node_id,
            node_kind=conflict.node_kind,
        )
        for conflict in ordered
    ]


def _emit_conflict_resolutions(
    event_emitter,
    conflicts: list[_ConflictResolutionTarget],
    *,
    resolution_status: str,
    resolution_reason: str,
) -> dict[str, str]:
    resolution_event_ids: dict[str, str] = {}
    for conflict in conflicts:
        if conflict.node_kind == "folder":
            event = event_emitter.emit_folder_conflict_resolved(
                conflict_id=conflict.conflict_id,
                node_id=conflict.node_id,
                resolution_status=resolution_status,
                resolution_reason=resolution_reason,
            )
        else:
            event = event_emitter.emit_file_conflict_resolved(
                conflict_id=conflict.conflict_id,
                node_id=conflict.node_id,
                resolution_status=resolution_status,
                resolution_reason=resolution_reason,
            )
        resolution_event_ids[conflict.conflict_id] = event.event_id
    return resolution_event_ids


def _resolve_conflicts_locally(
    session_factory,
    conflicts: list[_ConflictResolutionTarget],
    *,
    resolution_status: str,
    resolution_event_ids: dict[str, str] | None = None,
) -> None:
    if not conflicts:
        return

    with session_scope(session_factory) as session:
        for conflict in conflicts:
            resolution_event_id = (
                resolution_event_ids.get(conflict.conflict_id)
                if resolution_event_ids is not None
                else None
            ) or local_resolution_event_id(conflict.conflict_id, resolution_status)
            resolve_sync_conflict(
                session,
                conflict_id=conflict.conflict_id,
                resolution_event_id=resolution_event_id,
                status=resolution_status,
            )
