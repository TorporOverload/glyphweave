from __future__ import annotations

import html
import json
from typing import TYPE_CHECKING

from app.infrastructure.persistence.db.service.search import (
    get_retriable_extractions,
    search_content,
    search_file_references,
)
from app.infrastructure.persistence.db.service.sync_conflict_service import (
    get_sync_conflict_by_id,
    list_active_sync_conflicts,
    list_all_sync_conflicts,
)
from app.infrastructure.persistence.db.service.session import session_scope
from app.services.content.extraction_service import ExtractionService
from app.services.models import SearchPage, SearchResult, SyncConflictInfo

if TYPE_CHECKING:
    from app.infrastructure.persistence.db.model.sync_conflict import SyncConflict
    from app.services.vault_files.vault_file_service import VaultFileService


def list_root_entries(service: VaultFileService):
    return service._require_folder_service().get_root_entries()


def list_children(service: VaultFileService, parent_id: int):
    return service._require_folder_service().get_children(parent_id)


def list_all_entries(service: VaultFileService):
    return service._require_folder_service().get_vault_tree()


def get_file_reference_metadata(
    service: VaultFileService, file_ref_id: int
) -> dict:
    file_ref = service._require_file_service().get_file_reference_with_blobs(
        file_ref_id
    )
    if file_ref is None:
        raise FileNotFoundError(f"File reference not found: {file_ref_id}")
    if file_ref.is_folder:
        raise IsADirectoryError(f"Reference {file_ref_id} is a folder")
    if file_ref.file_entry is None:
        raise FileNotFoundError(f"File entry not found for reference: {file_ref_id}")

    metadata_json = file_ref.file_entry.metadata_json
    if not metadata_json:
        return {}
    return json.loads(metadata_json)


def search(
    service: VaultFileService, query: str, limit: int = 20
) -> list[SearchResult]:
    return search_page(service, query, limit=limit, offset=0).results


def search_page(
    service: VaultFileService,
    query: str,
    limit: int = 20,
    offset: int = 0,
    scope: str = "all",
) -> SearchPage:
    """Return one page of search results.

    ``scope`` selects which index branches are queried:
      * ``"all"``      — filename and content.
      * ``"filename"`` — filename matches only.
      * ``"content"``  — full-text content matches only.
    """
    if scope not in ("all", "filename", "content"):
        raise ValueError(f"Unknown search scope: {scope!r}")

    normalized = query.strip()
    if not normalized:
        return SearchPage(results=[], has_more=False)
    if service.context.session_factory is None:
        raise RuntimeError("Session factory is not initialized")

    from sqlalchemy import select

    from app.infrastructure.persistence.db.model.file_reference import FileReference

    with session_scope(service.context.session_factory, commit=False) as session:
        fetch_limit = max(limit + offset + 1, 1)
        results: list[SearchResult] = []
        seen_ref_ids: set[int] = set()

        if scope in ("all", "filename"):
            for ref_id, file_name, virtual_path, rank in search_file_references(
                session, normalized, fetch_limit
            ):
                results.append(
                    SearchResult(
                        file_ref_id=ref_id,
                        file_name=file_name,
                        virtual_path=virtual_path,
                        snippet=service._format_filename_snippet(
                            file_name, normalized
                        ),
                        rank=rank,
                    )
                )
                seen_ref_ids.add(ref_id)

        if scope in ("all", "content"):
            for file_entry_id, snippet, rank in search_content(
                session, normalized, fetch_limit
            ):
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


def reindex_pending(
    service: VaultFileService, limit: int = 500
) -> tuple[int, int]:
    if service.context.session_factory is None:
        raise RuntimeError("Session factory is not initialized")

    indexing_service = service._build_indexing_service()
    if indexing_service is None:
        raise RuntimeError("Indexing service is not available")

    with session_scope(service.context.session_factory, commit=False) as session:
        entries = get_retriable_extractions(session, limit=limit)

    success = 0
    failed = 0
    for entry in entries:
        filename = service._select_supported_reference_name(entry)
        if filename is None:
            continue

        if indexing_service.index_file_entry(entry, filename):
            success += 1
        else:
            failed += 1

    return success, failed


def get_db_debug_info(service: VaultFileService) -> dict:
    local_data_path = service.context.local_data_path
    if local_data_path is None:
        raise RuntimeError("Local data path is not set")
    return {
        "db_path": local_data_path / "vault.db",
        "vault_path": service.context.vault_path,
        "db_key": service.context.db_key_hex,
    }


def get_recovery_phrase(service: VaultFileService) -> str:
    key_service = service.context.key_service
    if not key_service or not key_service.master_key:
        raise RuntimeError("Vault is not unlocked")
    return key_service.unwrap_recovery_phrase_with_master()


def list_sync_conflicts(
    service: VaultFileService, *, include_resolved: bool = False
) -> list[SyncConflictInfo]:
    session_factory = service.context.session_factory
    if session_factory is None:
        raise RuntimeError("Session factory is not initialized")

    with session_scope(session_factory, commit=False) as session:
        conflicts = (
            list_all_sync_conflicts(session)
            if include_resolved
            else list_active_sync_conflicts(session)
        )
        return [_to_sync_conflict_info(conflict) for conflict in conflicts]


def get_sync_conflict(
    service: VaultFileService, conflict_id: str
) -> SyncConflictInfo | None:
    session_factory = service.context.session_factory
    if session_factory is None:
        raise RuntimeError("Session factory is not initialized")

    with session_scope(session_factory, commit=False) as session:
        conflict = get_sync_conflict_by_id(session, conflict_id)
        if conflict is None:
            return None
        return _to_sync_conflict_info(conflict)


def select_supported_reference_name(entry) -> str | None:
    for ref in getattr(entry, "references", []):
        name = getattr(ref, "name", "")
        if name and ExtractionService.is_supported(name):
            return name
    return None


def _to_sync_conflict_info(conflict: "SyncConflict") -> SyncConflictInfo:
    return SyncConflictInfo(
        conflict_id=conflict.conflict_id,
        node_id=conflict.node_id,
        node_kind=conflict.node_kind,
        archived_name=conflict.archived_name,
        archived_virtual_path=conflict.archived_virtual_path,
        reason_code=conflict.reason_code,
        reason_text=conflict.reason_text,
        trigger_event_id=conflict.trigger_event_id,
        trigger_event_hash=conflict.trigger_event_hash,
        trigger_event_type=conflict.trigger_event_type,
        origin_device_id=conflict.origin_device_id,
        status=conflict.status,
        created_at=conflict.created_at,
        archived_file_ref_id=conflict.archived_file_ref_id,
    )


def get_trigger_event_payload(
    service: VaultFileService, conflict_id: str
) -> dict | None:
    """Load the raw JSON payload of the event that produced ``conflict_id``.

    Returns None when the event store is unavailable, the conflict has no
    trigger hash, or the event object can't be read. Used by the conflict
    dialog's "Inspect trigger event" overlay.
    """
    session_factory = service.context.session_factory
    event_store = service.context.event_store
    if session_factory is None or event_store is None:
        return None

    with session_scope(session_factory, commit=False) as session:
        conflict = get_sync_conflict_by_id(session, conflict_id)
        if conflict is None or not conflict.trigger_event_hash:
            return None
        event_hash = conflict.trigger_event_hash

    try:
        path = event_store.object_path(event_hash)
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def format_filename_snippet(file_name: str, query: str) -> str:
    lower_name = file_name.lower()
    lower_query = query.lower()
    pos = lower_name.find(lower_query)

    if pos == -1:
        return f"Filename: {html.escape(file_name)}"

    before = file_name[:pos]
    match = file_name[pos : pos + len(query)]
    after = file_name[pos + len(query) :]
    return (
        f"Filename: {html.escape(before)}<b>{html.escape(match)}</b>"
        f"{html.escape(after)}"
    )
