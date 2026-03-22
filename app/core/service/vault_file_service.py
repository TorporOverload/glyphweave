from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from app.core.database.service.search import (
    get_retriable_extractions,
    search_content,
    search_file_references,
)
from app.core.database.service.session import session_scope
from app.core.runtime_layout import runtime_cache_dir
from app.core.service.extraction_service import ExtractionService
from app.core.service.indexing_service import IndexingService
from app.core.service.models import (
    AddFileResult,
    OpenFileResult,
    PendingFallbackOpen,
    SearchPage,
    SearchResult,
    UnlockedFileInfo,
    VaultContext,
)
from app.core.sync.event_emitter import EventEmitter
from app.core.service.vault_file_fallback import finalize_fallback_open
from app.core.service.vault_file_import import add_file as add_file_to_vault
from app.core.service.vault_file_mounts import reopen_mounted_file, unmount_mounted_file
from app.core.service.vault_file_opening import open_file_by_ref as open_file_from_vault
from app.core.service.vault_file_sessions import (
    cleanup_unlocked_files,
)
from app.core.service.vault_file_sessions import (
    list_unlocked_files as list_unlocked_file_sessions,
)

if TYPE_CHECKING:
    from app.core.crypto.service.encryption_service import EncryptionService
    from app.core.database.service.file_service import FileService
    from app.core.database.service.folder_service import FolderService


class VaultFileService:
    def __init__(self, context: VaultContext):
        self.context = context
        self.fallback_opens: dict[int, PendingFallbackOpen] = {}

    def list_root_entries(self):
        """Return all top-level file and folder entries in the vault."""
        folder_service = self._require_folder_service()
        return folder_service.get_root_entries()

    def list_children(self, parent_id: int):
        """Return all child entries of the given folder."""
        folder_service = self._require_folder_service()
        return folder_service.get_children(parent_id)

    def list_all_entries(self):
        """Return all vault entries in tree order."""
        folder_service = self._require_folder_service()
        return folder_service.get_vault_tree()

    def add_file(
        self,
        source,
        dest_name: str | None = None,
        dest_parent_virtual_path: str | None = None,
    ) -> AddFileResult:
        """Encrypt and import a file into the vault at the specified virtual path."""
        return add_file_to_vault(
            self.context,
            file_service=self._require_file_service(),
            folder_service=self._require_folder_service(),
            encryption_service=self._require_encryption_service(),
            indexing_service=self._build_indexing_service(),
            event_emitter=self._build_event_emitter(),
            source=source,
            dest_name=dest_name,
            dest_parent_virtual_path=dest_parent_virtual_path,
        )

    def open_file_by_ref(
        self,
        file_ref_id: int,
        launch_in_default_app: bool = True,
    ) -> OpenFileResult:
        """Open a vault file by reference ID, launching it in the default app if
        requested."""
        return open_file_from_vault(
            self.context,
            fallback_opens=self.fallback_opens,
            file_service=self._require_file_service(),
            encryption_service=self._require_encryption_service(),
            file_ref_id=file_ref_id,
            launch_in_default_app=launch_in_default_app,
        )

    def list_unlocked_files(self) -> list[UnlockedFileInfo]:
        """Return all currently unlocked files from both FUSE mounts and fallback
        cache."""
        return list_unlocked_file_sessions(self.context, self.fallback_opens)

    def get_file_reference_metadata(self, file_ref_id: int) -> dict:
        """Return parsed metadata for a file reference."""
        file_ref = self._require_file_service().get_file_reference_with_blobs(
            file_ref_id
        )
        if file_ref is None:
            raise FileNotFoundError(f"File reference not found: {file_ref_id}")
        if file_ref.is_folder:
            raise IsADirectoryError(f"Reference {file_ref_id} is a folder")
        if file_ref.file_entry is None:
            raise FileNotFoundError(
                f"File entry not found for reference: {file_ref_id}"
            )

        metadata_json = file_ref.file_entry.metadata_json
        if not metadata_json:
            return {}
        return json.loads(metadata_json)

    def search(self, query: str, limit: int = 20) -> list[SearchResult]:
        """Search indexed document content and resolve matches to visible file refs."""
        return self.search_page(query, limit=limit, offset=0).results

    def search_page(
        self,
        query: str,
        limit: int = 20,
        offset: int = 0,
    ) -> SearchPage:
        """Return one page of ranked search results and whether more results exist."""
        normalized = query.strip()
        if not normalized:
            return SearchPage(results=[], has_more=False)
        if self.context.session_factory is None:
            raise RuntimeError("Session factory is not initialized")

        from sqlalchemy import select

        from app.core.database.model.file_reference import FileReference

        with session_scope(self.context.session_factory, commit=False) as session:
            fetch_limit = max(limit + offset + 1, 1)
            results: list[SearchResult] = []
            seen_ref_ids: set[int] = set()

            for ref_id, file_name, virtual_path, rank in search_file_references(
                session, normalized, fetch_limit
            ):
                results.append(
                    SearchResult(
                        file_ref_id=ref_id,
                        file_name=file_name,
                        virtual_path=virtual_path,
                        snippet=self._format_filename_snippet(file_name, normalized),
                        rank=rank,
                    )
                )
                seen_ref_ids.add(ref_id)

            fts_results = search_content(session, normalized, fetch_limit)
            for file_entry_id, snippet, rank in fts_results:
                refs = session.scalars(
                    select(FileReference)
                    .where(
                        FileReference.file_entry_id == int(file_entry_id),
                        FileReference.is_folder.is_(False),
                    )
                    .order_by(FileReference.id)
                ).all()
                for ref in refs:
                    if ref.id in seen_ref_ids:
                        continue
                    results.append(
                        SearchResult(
                            file_ref_id=ref.id,
                            file_name=ref.name,
                            virtual_path=ref.virtual_path,
                            snippet=snippet,
                            rank=rank,
                        )
                    )
                    seen_ref_ids.add(ref.id)

            page_results = results[offset : offset + limit]
            return SearchPage(
                results=page_results,
                has_more=len(results) > offset + limit,
            )

    def reindex_pending(self, limit: int = 500) -> tuple[int, int]:
        """Retry indexing for supported files in pending or failed state."""
        if self.context.session_factory is None:
            raise RuntimeError("Session factory is not initialized")

        indexing_service = self._build_indexing_service()
        if indexing_service is None:
            raise RuntimeError("Indexing service is not available")

        with session_scope(self.context.session_factory, commit=False) as session:
            entries = get_retriable_extractions(session, limit=limit)

        success = 0
        failed = 0
        for entry in entries:
            filename = self._select_supported_reference_name(entry)
            if filename is None:
                continue

            if indexing_service.index_file_entry(entry, filename):
                success += 1
            else:
                failed += 1

        return success, failed

    def reopen_unlocked(self, file_ref_id: int) -> str:
        """Re-launch a currently unlocked file in the default application."""
        mounted = reopen_mounted_file(self.context, file_ref_id)
        if mounted is not None:
            return mounted

        pending = self.fallback_opens.get(file_ref_id)
        if pending and pending.temp_path.exists():
            from app.core.service.launcher_service import open_with_default_app

            open_with_default_app(pending.temp_path)
            return "Opened cached decrypted file"

        raise FileNotFoundError("File is not currently unlocked")

    def unmount_unlocked(self, file_ref_id: int) -> str:
        """Unmount or finalize a currently unlocked file and save any changes."""
        mounted = unmount_mounted_file(self.context, file_ref_id)
        if mounted is not None:
            return mounted

        return finalize_fallback_open(
            self.context,
            fallback_opens=self.fallback_opens,
            file_service=self._require_file_service(),
            folder_service=self._require_folder_service(),
            encryption_service=self._require_encryption_service(),
            event_emitter=self._build_event_emitter(),
            file_ref_id=file_ref_id,
        )

    def cleanup(self) -> None:
        """Finalize all open files, unmount FUSE filesystems, and dispose the database
        engine."""
        runtime = self.context.event_replay_runtime
        if runtime is not None:
            runtime.stop()
            self.context.event_replay_runtime = None
        cleanup_unlocked_files(
            self.context,
            fallback_opens=self.fallback_opens,
            file_service=self._require_file_service(),
            folder_service=self._require_folder_service(),
            encryption_service=self._require_encryption_service(),
        )

    def copy_entry(
        self,
        source_virtual_path: str,
        destination_folder_virtual_path: str = "/",
        new_name: str | None = None,
    ):
        """Copy a file or folder inside the vault."""
        source = self._get_entry_by_virtual_path(source_virtual_path)
        if source is None:
            raise FileNotFoundError(f"Vault entry not found: {source_virtual_path}")

        destination_parent_id = self._resolve_or_create_destination_parent_id(
            destination_folder_virtual_path
        )
        if source.is_folder and self._is_descendant_path(
            destination_folder_virtual_path,
            source.virtual_path,
        ):
            raise ValueError("Cannot copy a folder into itself or its descendant")

        return self._copy_reference(
            source.id,
            destination_parent_id,
            new_name=new_name,
        )

    def move_entries(
        self,
        source_virtual_paths: list[str],
        destination_folder_virtual_path: str = "/",
    ):
        """Move multiple files or folders into another vault folder."""
        if not source_virtual_paths:
            return []

        entries = self._resolve_entries(source_virtual_paths)
        self._ensure_no_nested_selection(entries)
        destination_parent_id = self._resolve_or_create_destination_parent_id(
            destination_folder_virtual_path
        )

        names = [entry.name for entry in entries]
        if len(set(names)) != len(names):
            raise ValueError(
                """Cannot move multiple entries with the same name
                into one destination folder"""
            )

        folder_service = self._require_folder_service()
        moving_ids = {entry.id for entry in entries}
        for entry in entries:
            existing = folder_service.get_child_by_name(
                destination_parent_id, entry.name
            )
            if existing is not None and existing.id not in moving_ids:
                raise FileExistsError(
                    f"An entry named '{entry.name}' already exists in the destination"
                )

        moved = []
        for entry in entries:
            if entry.is_folder and self._is_descendant_path(
                destination_folder_virtual_path,
                entry.virtual_path,
            ):
                raise ValueError("Cannot move a folder into itself or its descendant")
            folder_service.rename_entry(entry.id, entry.name, destination_parent_id)
            updated_entry = self._get_entry_by_id(entry.id)
            self._emit_move_event(updated_entry, destination_parent_id, entry.name)
            moved.append(updated_entry)
        return moved

    def delete_entries(self, source_virtual_paths: list[str]) -> int:
        """Delete one or more files or folders from the vault."""
        if not source_virtual_paths:
            return 0

        entries = self._resolve_entries(source_virtual_paths)
        entries = self._collapse_descendant_entries(entries)
        folder_service = self._require_folder_service()
        event_emitter = self._build_event_emitter()
        orphan_ids: list[int] = []
        for entry in entries:
            if event_emitter is not None:
                self._emit_delete_event(entry)
            orphan_ids.extend(folder_service.delete_entry(entry.id))
        folder_service.gc.cleanup_batch(orphan_ids)
        return len(entries)

    def rename_entry(self, source_virtual_path: str, new_name: str):
        """Rename a single file or folder without changing its parent."""
        source = self._get_entry_by_virtual_path(source_virtual_path)
        if source is None:
            raise FileNotFoundError(f"Vault entry not found: {source_virtual_path}")

        self._require_folder_service().rename_entry(
            source.id, new_name, source.parent_id
        )
        updated_entry = self._get_entry_by_id(source.id)
        self._emit_move_event(updated_entry, source.parent_id, new_name)
        return updated_entry

    def export_entries(
        self,
        source_virtual_paths: list[str],
        destination_dir: Path,
    ) -> list[Path]:
        """Export one or more files or folders to a filesystem directory."""
        if not source_virtual_paths:
            return []

        entries = self._resolve_entries(source_virtual_paths)
        self._ensure_no_nested_selection(entries)

        destination_root = Path(destination_dir)
        destination_root.mkdir(parents=True, exist_ok=True)
        exported: list[Path] = []
        for entry in entries:
            exported.append(
                self._export_reference(entry.id, destination_root, override_name=None)
            )
        return exported

    def get_db_debug_info(self) -> dict:
        """Return debug information about the vault database path and encryption
        key."""
        local_data_path = self.context.local_data_path
        if local_data_path is None:
            raise RuntimeError("Local data path is not set")
        return {
            "db_path": local_data_path / "vault.db",
            "vault_path": self.context.vault_path,
            "db_key": self.context.db_key_hex,
        }

    def get_recovery_phrase(self) -> str:
        """Return the vault's recovery phrase by decrypting it with the master key."""
        key_service = self.context.key_service
        if not key_service or not key_service.master_key:
            raise RuntimeError("Vault is not unlocked")
        return key_service.unwrap_recovery_phrase_with_master()

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
        if self.context.vault_path is None:
            return None
        self.context.event_emitter = EventEmitter(
            vault_path=self.context.vault_path,
            app_data_dir=self.context.app_data_dir,
        )
        return self.context.event_emitter

    @staticmethod
    def _select_supported_reference_name(entry) -> str | None:
        for ref in getattr(entry, "references", []):
            name = getattr(ref, "name", "")
            if name and ExtractionService.is_supported(name):
                return name
        return None

    @staticmethod
    def _format_filename_snippet(file_name: str, query: str) -> str:
        exact_index = file_name.find(query)
        if exact_index >= 0:
            return (
                f"Filename: {file_name[:exact_index]}<b>{
                    file_name[exact_index : exact_index + len(query)]
                }</b>"
                f"{file_name[exact_index + len(query) :]}"
            )

        lower_name = file_name.lower()
        lower_query = query.lower()
        lower_index = lower_name.find(lower_query)
        if lower_index >= 0:
            return (
                f"Filename: {file_name[:lower_index]}<b>{
                    file_name[lower_index : lower_index + len(query)]
                }</b>"
                f"{file_name[lower_index + len(query) :]}"
            )

        return f"Filename: {file_name}"

    def _require_file_service(self) -> "FileService":
        """Return the file service or raise if not initialized."""
        if self.context.file_service is None:
            raise RuntimeError("File service is not initialized")
        return self.context.file_service

    def _require_folder_service(self) -> "FolderService":
        """Return the folder service or raise if not initialized."""
        if self.context.folder_service is None:
            raise RuntimeError("Folder service is not initialized")
        return self.context.folder_service

    def _require_encryption_service(self) -> "EncryptionService":
        """Return the encryption service or raise if not initialized."""
        if self.context.encryption_service is None:
            raise RuntimeError("Encryption service is not initialized")
        return self.context.encryption_service

    def _get_entry_by_id(self, ref_id: int):
        entry = self._require_folder_service().get_by_id(ref_id)
        if entry is None:
            raise FileNotFoundError(f"Vault entry not found: {ref_id}")
        return entry

    def _get_entry_by_virtual_path(self, virtual_path: str):
        normalized = self._normalize_vault_path(virtual_path)
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

    def _get_destination_parent_id(self, virtual_path: str) -> int | None:
        normalized = self._normalize_vault_path(virtual_path)
        if normalized == "/":
            return None

        folder = self._get_entry_by_virtual_path(normalized)
        if folder is None:
            raise FileNotFoundError(f"Destination folder not found: {virtual_path}")
        if not folder.is_folder:
            raise NotADirectoryError(f"Destination is not a folder: {virtual_path}")
        return folder.id

    def _resolve_or_create_destination_parent_id(self, virtual_path: str) -> int | None:
        normalized = self._normalize_vault_path(virtual_path)
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
        self,
        entry,
        destination_parent_id: int | None,
        new_name: str,
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

    def _emit_delete_event(self, entry) -> None:
        event_emitter = self._build_event_emitter()
        if event_emitter is None:
            return
        if entry.is_folder:
            event_emitter.emit_folder_delete(entry, cascade=True)
            return
        file_id = None
        if entry.file_entry_id is not None:
            hydrated = self._require_file_service().get_file_reference_with_blobs(entry.id)
            if hydrated is not None and hydrated.file_entry is not None:
                file_id = hydrated.file_entry.file_id
        event_emitter.emit_file_delete(entry, file_id=file_id)

    @staticmethod
    def _normalize_vault_path(path: str | None) -> str:
        if path is None:
            return "/"

        normalized = path.strip().replace("\\", "/")
        if not normalized:
            return "/"

        parts = [
            segment for segment in normalized.split("/") if segment not in {"", "."}
        ]
        if any(segment == ".." for segment in parts):
            raise ValueError("Parent traversal ('..') is not allowed")

        if not parts:
            return "/"
        return "/" + "/".join(parts)

    @staticmethod
    def _is_descendant_path(candidate_path: str, parent_path: str) -> bool:
        normalized_candidate = VaultFileService._normalize_vault_path(candidate_path)
        normalized_parent = VaultFileService._normalize_vault_path(parent_path)
        return (
            normalized_candidate == normalized_parent
            or normalized_candidate.startswith(normalized_parent + "/")
        )

    @staticmethod
    def _ensure_no_nested_selection(entries) -> None:
        ordered_paths = sorted(entry.virtual_path for entry in entries)
        for index, path in enumerate(ordered_paths):
            for later in ordered_paths[index + 1 :]:
                if later.startswith(path + "/"):
                    raise ValueError(
                        "Nested selections are not allowed for this operation"
                    )

    @staticmethod
    def _collapse_descendant_entries(entries):
        kept = []
        for entry in sorted(entries, key=lambda item: len(item.virtual_path)):
            if any(
                entry.virtual_path.startswith(parent.virtual_path + "/")
                for parent in kept
            ):
                continue
            kept.append(entry)
        return kept

    def _copy_reference(
        self,
        source_ref_id: int,
        destination_parent_id: int | None,
        *,
        new_name: str | None = None,
    ):
        source = self._get_entry_by_id(source_ref_id)
        target_name = new_name or source.name
        if source.is_folder:
            created_folder = self._require_folder_service().create_folder(
                target_name,
                destination_parent_id,
            )
            event_emitter = self._build_event_emitter()
            if event_emitter is not None:
                event_emitter.emit_folder_create(created_folder)
            for child in self._require_folder_service().get_children(source.id):
                self._copy_reference(child.id, created_folder.id)
            return created_folder

        if source.file_entry_id is None:
            raise RuntimeError(f"File reference {source.id} has no file entry")
        created_ref = self._require_file_service().create_file_reference(
            name=target_name,
            parent_id=destination_parent_id,
            file_entry_id=source.file_entry_id,
        )
        event_emitter = self._build_event_emitter()
        if event_emitter is not None:
            event_emitter.emit_file_add(created_ref)
        return created_ref

    def _export_reference(
        self,
        source_ref_id: int,
        destination_parent: Path,
        *,
        override_name: str | None = None,
    ) -> Path:
        source = self._get_entry_by_id(source_ref_id)
        target_path = destination_parent / (override_name or source.name)
        if target_path.exists():
            raise FileExistsError(f"Export destination already exists: {target_path}")
        if source.is_folder:
            target_path.mkdir(parents=True, exist_ok=False)
            for child in self._require_folder_service().get_children(source.id):
                self._export_reference(child.id, target_path)
            return target_path

        file_ref = self._require_file_service().get_file_reference_with_blobs(source.id)
        if file_ref is None or file_ref.file_entry is None:
            raise FileNotFoundError(f"Vault file not found: {source.virtual_path}")

        vault_path = self.context.require_vault_path()
        vault_id = self.context.require_vault_id().encode("utf-8")
        master_key = self.context.require_master_key().view()
        blob_ids = [blob.blob_id for blob in file_ref.file_entry.blobs]
        target_path.parent.mkdir(parents=True, exist_ok=True)
        self._require_encryption_service().decrypt_file(
            vault_path=vault_path,
            blob_ids=blob_ids,
            output_path=target_path,
            master_key=master_key,
            vault_id=vault_id,
            file_id=file_ref.file_entry.file_id,
        )
        return target_path
