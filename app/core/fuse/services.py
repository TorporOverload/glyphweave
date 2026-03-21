"""Shared service construction for FUSE filesystem components."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from app.core.database.service.file_service import FileService
from app.core.database.service.folder_service import FolderService
from app.core.database.service.gc_service import GarbageCollector
from app.core.database.service.wal_service import WalService
from app.core.fuse.temp_store import TempStore

if TYPE_CHECKING:
    from sqlalchemy.orm import sessionmaker

    from app.core.crypto.service.key_service import KeyService


@dataclass
class FuseServiceBundle:
    """Container for the set of services shared by FuseOrchestrator and SingleFileFS."""

    file_service: FileService
    folder_service: FolderService
    gc: GarbageCollector
    wal_service: WalService
    temp_store: TempStore
    session_factory: sessionmaker


def build_fuse_services(
    session_factory: sessionmaker,
    vault_path: Path,
    cache_dir: Path,
    key_service: KeyService,
) -> FuseServiceBundle:
    """Construct the standard set of FUSE services from a session factory."""
    temp_store = TempStore(cache_dir=cache_dir, key_service=key_service)
    return FuseServiceBundle(
        file_service=FileService(session_factory),
        folder_service=FolderService(session_factory, vault_path),
        gc=GarbageCollector(session_factory, vault_path),
        wal_service=WalService(session_factory=session_factory, temp_store=temp_store),
        temp_store=temp_store,
        session_factory=session_factory,
    )
