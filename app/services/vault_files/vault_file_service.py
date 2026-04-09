from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from app.common.paths.runtime_layout import runtime_cache_dir
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.services.content.indexing_service import IndexingService
from app.services.models import (
    PendingFallbackOpen,
    SearchPage,
    SearchResult,
    SyncConflictInfo,
    UnlockedFileInfo,
    VaultContext,
)
from app.services.runtime.event_store_factory import build_event_store
from app.services.sync.event_emitter import EventEmitter

from . import access, commands, queries
from .helpers import normalize_vault_path

if TYPE_CHECKING:
    from app.services.models import AddFileResult


class VaultFileService:
    def __init__(self, context: VaultContext):
        self.context = context
        self.fallback_opens: dict[int, PendingFallbackOpen] = {}

    def _build_indexing_service(self) -> IndexingService | None:
        local_data_path = self.context.local_data_path
        if (
            self.context.session_factory is None
            or self.context.encryption_service is None
            or self.context.vault_path is None
            or self.context.vault_id is None
            or self.context.master_key is None
            or local_data_path is None
        ):
            return None

        return IndexingService(
            session_factory=self.context.session_factory,
            encryption_service=self.context.encryption_service,
            vault_path=self.context.vault_path,
            cache_dir=runtime_cache_dir(local_data_path),
            master_key=self.context.master_key.view(),
            vault_id=self.context.vault_id,
        )

    def _build_event_emitter(self) -> EventEmitter | None:
        if self.context.event_emitter is not None:
            return self.context.event_emitter
        if (
            self.context.vault_path is None
            or self.context.vault_id is None
            or self.context.master_key is None
        ):
            return None
        self.context.event_emitter = EventEmitter(
            store=build_event_store(self.context),
            app_data_dir=self.context.app_data_dir,
            session_factory=self.context.session_factory,
            local_data_path=self.context.local_data_path,
        )
        return self.context.event_emitter

    def _require_file_service(self):
        if self.context.file_service is None:
            raise RuntimeError("File service is not initialized")
        return self.context.file_service

    def _require_folder_service(self):
        if self.context.folder_service is None:
            raise RuntimeError("Folder service is not initialized")
        return self.context.folder_service

    def _require_encryption_service(self):
        if self.context.encryption_service is None:
            raise RuntimeError("Encryption service is not initialized")
        return self.context.encryption_service

    def _get_entry_by_id(self, ref_id: int):
        entry = self._require_folder_service().get_by_id(ref_id)
        if entry is None:
            raise FileNotFoundError(f"Vault entry not found: {ref_id}")
        return entry

    def _get_entry_by_virtual_path(self, virtual_path: str):
        normalized = normalize_vault_path(virtual_path)
        return self._require_folder_service().get_by_virtual_path(normalized)

    def _resolve_entries(self, source_virtual_paths: list[str]):
        resolved = []
        seen_paths: set[str] = set()
        for path in source_virtual_paths:
            entry = self._get_entry_by_virtual_path(path)
            if entry is None:
                raise FileNotFoundError(f"Vault entry not found: {path}")
            if entry.virtual_path in seen_paths:
                continue
            seen_paths.add(entry.virtual_path)
            resolved.append(entry)
        return resolved

    def _resolve_or_create_destination_parent_id(self, virtual_path: str) -> int | None:
        normalized = normalize_vault_path(virtual_path)
        if normalized == "/":
            return None

        folder_service = self._require_folder_service()
        event_emitter = self._build_event_emitter()
        parent_id: int | None = None
        traversed: list[str] = []
        for segment in normalized.strip("/").split("/"):
            traversed.append(segment)
            existing = folder_service.get_child_by_name(parent_id, segment)
            if existing is None:
                existing = folder_service.create_folder(segment, parent_id)
                if event_emitter is not None:
                    event_emitter.emit_folder_create(existing)
            elif not existing.is_folder:
                bad_path = "/" + "/".join(traversed)
                raise NotADirectoryError(
                    f"Destination path segment is not a folder: {bad_path}"
                )
            parent_id = existing.id
        return parent_id

    def _emit_move_event(
        self, entry, destination_parent_id: int | None, new_name: str
    ) -> None:
        event_emitter = self._build_event_emitter()
        if event_emitter is None:
            return
        parent_node_id = None
        if destination_parent_id is not None:
            parent = self._get_entry_by_id(destination_parent_id)
            parent_node_id = parent.node_id
        if entry.is_folder:
            event_emitter.emit_folder_move(
                entry,
                new_parent_node_id=parent_node_id,
                new_name=new_name,
            )
        else:
            event_emitter.emit_file_move(
                entry,
                new_parent_node_id=parent_node_id,
                new_name=new_name,
            )

    def _emit_delete_event(self, entry, *, file_id: str | None = None) -> None:
        event_emitter = self._build_event_emitter()
        if event_emitter is None:
            return
        if entry.is_folder:
            event_emitter.emit_folder_delete(entry, cascade=True)
            return
        resolved_file_id = file_id
        if resolved_file_id is None and entry.file_entry_id is not None:
            hydrated = self._require_file_service().get_file_reference_with_blobs(
                entry.id
            )
            if hydrated is not None and hydrated.file_entry is not None:
                resolved_file_id = hydrated.file_entry.file_id
        event_emitter.emit_file_delete(entry, file_id=resolved_file_id)

    def add_file(
        self,
        source: Path,
        dest_name: str | None = None,
        dest_parent_virtual_path: str | None = None,
    ) -> "AddFileResult":
        return commands.add_file(self, source, dest_name, dest_parent_virtual_path)

    def create_folder(self, name: str, parent_virtual_path: str = "/"):
        return commands.create_folder(self, name, parent_virtual_path)

    def copy_entry(
        self,
        source_virtual_path: str,
        destination_folder_virtual_path: str = "/",
        new_name: str | None = None,
    ) -> FileReference:
        return commands.copy_entry(
            self, source_virtual_path, destination_folder_virtual_path, new_name
        )

    def move_entries(
        self,
        source_virtual_paths: list[str],
        destination_folder_virtual_path: str = "/",
    ) -> list[FileReference]:
        return commands.move_entries(
            self, source_virtual_paths, destination_folder_virtual_path
        )

    def delete_entries(self, source_virtual_paths: list[str]) -> int:
        return commands.delete_entries(self, source_virtual_paths)

    def rename_entry(self, source_virtual_path: str, new_name: str):
        return commands.rename_entry(self, source_virtual_path, new_name)

    def restore_sync_conflict(
        self,
        conflict_id: str,
        destination_folder_virtual_path: str = "/",
        new_name: str | None = None,
    ) -> FileReference:
        return commands.restore_sync_conflict(
            self,
            conflict_id,
            destination_folder_virtual_path,
            new_name,
        )

    def export_entries(
        self, source_virtual_paths: list[str], destination_dir: Path
    ) -> list[Path]:
        return commands.export_entries(self, source_virtual_paths, destination_dir)

    def list_root_entries(self) -> list[FileReference]:
        return queries.list_root_entries(self)

    def list_children(self, parent_id: int) -> list[FileReference]:
        return queries.list_children(self, parent_id)

    def list_all_entries(self) -> list[FileReference]:
        return queries.list_all_entries(self)

    def get_file_reference_metadata(self, file_ref_id: int) -> dict:
        return queries.get_file_reference_metadata(self, file_ref_id)

    def search(self, query: str, limit: int = 20) -> list[SearchResult]:
        return queries.search(self, query, limit)

    def search_page(
        self, query: str, limit: int = 20, offset: int = 0
    ) -> SearchPage:
        return queries.search_page(self, query, limit, offset)

    def reindex_pending(self, limit: int = 500) -> tuple[int, int]:
        return queries.reindex_pending(self, limit)

    def get_db_debug_info(self) -> dict:
        return queries.get_db_debug_info(self)

    def get_recovery_phrase(self) -> str:
        return queries.get_recovery_phrase(self)

    def list_sync_conflicts(self) -> list[SyncConflictInfo]:
        return queries.list_sync_conflicts(self)

    def get_sync_conflict(self, conflict_id: str) -> SyncConflictInfo | None:
        return queries.get_sync_conflict(self, conflict_id)

    @staticmethod
    def _select_supported_reference_name(entry) -> str | None:
        return queries.select_supported_reference_name(entry)

    @staticmethod
    def _format_filename_snippet(file_name: str, query: str) -> str:
        return queries.format_filename_snippet(file_name, query)

    def open_file_by_ref(
        self, file_ref_id: int, launch_in_default_app: bool = True
    ):
        return access.open_file_by_ref(self, file_ref_id, launch_in_default_app)

    def list_unlocked_files(self) -> list[UnlockedFileInfo]:
        return access.list_unlocked(self)

    def reopen_unlocked(self, file_ref_id: int) -> str:
        return access.reopen_unlocked(self, file_ref_id)

    def unmount_unlocked(self, file_ref_id: int) -> str:
        return access.unmount_unlocked(self, file_ref_id)

    def cleanup(self, *, flush_db_dump: bool = True) -> None:
        access.cleanup(self, flush_db_dump=flush_db_dump)
