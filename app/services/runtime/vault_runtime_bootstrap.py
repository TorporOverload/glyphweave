from __future__ import annotations

import threading

from app.common.logging import logger
from app.common.paths.runtime_layout import runtime_cache_dir
from app.infrastructure.crypto.service.encryption_service import EncryptionService
from app.infrastructure.fuse.fuse_orchestrator import FuseOrchestrator
from app.infrastructure.persistence.db.base import DbBase
from app.infrastructure.persistence.db.service.file_service import FileService
from app.infrastructure.persistence.db.service.folder_service import FolderService
from app.infrastructure.persistence.db.service.search import get_retriable_extractions
from app.infrastructure.persistence.db.service.session import session_scope
from app.infrastructure.persistence.db_dump_service import (
    install_db_dump_hook,
    restore_latest_db_dump,
)
from app.services.content.extraction_service import ExtractionService
from app.services.content.indexing_service import IndexingService
from app.services.models import VaultContext
from app.services.runtime.event_store_factory import build_event_store
from app.services.sync.replay import replay_vault_events
from app.services.sync.runtime import EventReplayRuntime


def bootstrap_runtime_services(context: VaultContext) -> None:
    """Initialize the database, encryption, file services, and FUSE orchestrator for
    the vault."""
    vault_id = context.require_vault_id()
    vault_path = context.require_vault_path()
    local_data_path = context.local_data_path
    if local_data_path is None:
        raise RuntimeError("Local data path is not set")
    key_service = context.key_service
    if key_service is None:
        raise RuntimeError("Key service is not initialized")
    master_key = context.require_master_key()
    vaults_data_dir = context.app_data_dir / "vaults"

    context.db_key_hex = key_service.derive_database_key()
    db_path = DbBase.resolve_db_path(vault_id, vaults_data_dir)
    needs_local_db = not db_path.exists() or db_path.stat().st_size == 0
    if needs_local_db:
        restore_latest_db_dump(
            vault_path=vault_path,
            db_path=db_path,
            db_key_hex=context.db_key_hex,
        )
    context.db = DbBase(
        vault_id,
        context.db_key_hex,
        vaults_data_dir=vaults_data_dir,
    )
    missing_tables, missing_triggers = context.db.get_missing_schema_objects()
    if missing_tables or missing_triggers:
        logger.info(
            "Repairing vault schema; missing tables=%s missing triggers=%s",
            sorted(missing_tables),
            sorted(missing_triggers),
        )
        context.db.initialize_schema()
    context.encryption_service = EncryptionService()
    context.session_factory = context.db.SessionLocal
    context.event_store = build_event_store(context)
    replay_vault_events(
        session_factory=context.session_factory,
        vault_path=vault_path,
        store=context.event_store,
        local_data_path=local_data_path,
        app_data_dir=context.app_data_dir,
    )
    dump_service = install_db_dump_hook(
        session_factory=context.session_factory,
        vault_path=vault_path,
        db_path=context.db.db_path,
        db_key_hex=context.db_key_hex,
        app_data_dir=context.app_data_dir,
        event_store=context.event_store,
    )
    dump_service.maybe_create_dump()
    context.file_service = FileService(context.session_factory)
    context.folder_service = FolderService(context.session_factory, vault_path)
    _index_replayed_entries(context)
    if context.event_replay_runtime is None:
        context.event_replay_runtime = EventReplayRuntime(
            context=context,
            store=context.event_store,
            on_replayed=_index_replayed_entries,
        )
    context.event_replay_runtime.start()

    cache_dir = runtime_cache_dir(local_data_path)
    cache_dir.mkdir(parents=True, exist_ok=True)
    context.mounts = FuseOrchestrator(
        cache_dir=cache_dir,
        vault_path=vault_path,
        session_factory=context.session_factory,
        key_service=key_service,
        vault_id=vault_id.encode("utf-8"),
        master_key=master_key,
    )


def _index_replayed_entries(context: VaultContext) -> None:
    """Schedule indexing of replayed entries in a background thread.

    This prevents blocking the UI thread while text extraction and indexing
    operations are performed on potentially large files.
    """
    local_data_path = context.local_data_path
    if (
        context.session_factory is None
        or context.encryption_service is None
        or context.vault_path is None
        or context.vault_id is None
        or context.master_key is None
        or local_data_path is None
    ):
        return

    # Start indexing in a background thread to avoid blocking the main thread
    thread = threading.Thread(
        target=_run_indexing_in_background,
        args=(
            context.session_factory,
            context.encryption_service,
            context.vault_path,
            local_data_path,
            context.master_key.view(),
            context.vault_id,
        ),
        daemon=True,
        name="GlyphweaveIndexing",
    )
    thread.start()


def _run_indexing_in_background(
    session_factory,
    encryption_service,
    vault_path,
    local_data_path,
    master_key,
    vault_id,
) -> None:
    """Run indexing operations in a background thread."""
    try:
        indexing_service = IndexingService(
            session_factory=session_factory,
            encryption_service=encryption_service,
            vault_path=vault_path,
            cache_dir=runtime_cache_dir(local_data_path),
            master_key=master_key,
            vault_id=vault_id,
        )
        with session_scope(session_factory, commit=False) as session:
            entries = get_retriable_extractions(session, limit=500)

        for entry in entries:
            filename = _select_supported_reference_name(entry)
            if filename is None:
                continue
            indexing_service.index_file_entry(entry, filename)
    except Exception:
        logger.exception("Background indexing failed")


def _select_supported_reference_name(entry) -> str | None:
    for ref in getattr(entry, "references", []):
        name = getattr(ref, "name", "")
        if name and ExtractionService.is_supported(name):
            return name
    return None
