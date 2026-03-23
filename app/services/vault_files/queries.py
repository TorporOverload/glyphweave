from __future__ import annotations

import json

from app.infrastructure.persistence.db.service.search import (
    get_retriable_extractions,
    search_content,
    search_file_references,
)
from app.infrastructure.persistence.db.service.session import session_scope
from app.services.content.extraction_service import ExtractionService
from app.services.models import SearchPage, SearchResult


def list_root_entries(service):
    return service._require_folder_service().get_root_entries()


def list_children(service, parent_id: int):
    return service._require_folder_service().get_children(parent_id)


def list_all_entries(service):
    return service._require_folder_service().get_vault_tree()


def get_file_reference_metadata(service, file_ref_id: int) -> dict:
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


def search(service, query: str, limit: int = 20) -> list[SearchResult]:
    return search_page(service, query, limit=limit, offset=0).results


def search_page(service, query: str, limit: int = 20, offset: int = 0) -> SearchPage:
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

        for ref_id, file_name, virtual_path, rank in search_file_references(
            session, normalized, fetch_limit
        ):
            results.append(
                SearchResult(
                    file_ref_id=ref_id,
                    file_name=file_name,
                    virtual_path=virtual_path,
                    snippet=service._format_filename_snippet(file_name, normalized),
                    rank=rank,
                )
            )
            seen_ref_ids.add(ref_id)

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


def reindex_pending(service, limit: int = 500) -> tuple[int, int]:
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


def get_db_debug_info(service) -> dict:
    local_data_path = service.context.local_data_path
    if local_data_path is None:
        raise RuntimeError("Local data path is not set")
    return {
        "db_path": local_data_path / "vault.db",
        "vault_path": service.context.vault_path,
        "db_key": service.context.db_key_hex,
    }


def get_recovery_phrase(service) -> str:
    key_service = service.context.key_service
    if not key_service or not key_service.master_key:
        raise RuntimeError("Vault is not unlocked")
    return key_service.unwrap_recovery_phrase_with_master()


def select_supported_reference_name(entry) -> str | None:
    for ref in getattr(entry, "references", []):
        name = getattr(ref, "name", "")
        if name and ExtractionService.is_supported(name):
            return name
    return None


def format_filename_snippet(file_name: str, query: str) -> str:
    exact_index = file_name.find(query)
    if exact_index >= 0:
        return (
            f"Filename: {file_name[:exact_index]}<b>"
            f"{file_name[exact_index : exact_index + len(query)]}</b>"
            f"{file_name[exact_index + len(query) :]}"
        )

    lower_name = file_name.lower()
    lower_query = query.lower()
    lower_index = lower_name.find(lower_query)
    if lower_index >= 0:
        return (
            f"Filename: {file_name[:lower_index]}<b>"
            f"{file_name[lower_index : lower_index + len(query)]}</b>"
            f"{file_name[lower_index + len(query) :]}"
        )

    return f"Filename: {file_name}"
