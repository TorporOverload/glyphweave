from __future__ import annotations

from app.core.crypto.service.encryption_service import EncryptionService
from app.core.database.base import DbBase
from app.core.database.service.file_service import FileService
from app.core.database.service.folder_service import FolderService
from app.core.fuse.fuse_orchestrator import FuseOrchestrator
from app.core.runtime_layout import runtime_cache_dir

from .models import VaultContext


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
    context.db = DbBase(
        vault_id,
        context.db_key_hex,
        vaults_data_dir=vaults_data_dir,
    )
    context.encryption_service = EncryptionService()
    context.session_factory = context.db.SessionLocal
    context.file_service = FileService(context.session_factory)
    context.folder_service = FolderService(context.session_factory, vault_path)

    cache_dir = runtime_cache_dir(local_data_path)
    cache_dir.mkdir(parents=True, exist_ok=True)
    session = context.session_factory()
    context.mounts = FuseOrchestrator(
        cache_dir=cache_dir,
        vault_path=vault_path,
        db_session=session,
        key_service=key_service,
        vault_id=vault_id.encode("utf-8"),
        master_key=master_key,
    )
