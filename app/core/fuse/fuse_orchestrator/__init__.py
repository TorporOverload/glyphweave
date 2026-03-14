import json
import platform
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Dict

import mfusepy as fuse
from sqlalchemy.orm import Session, sessionmaker

from app.core.crypto.primitives.secure_memory import SecureMemory
from app.core.crypto.service.key_service import KeyService
from app.core.database.service.file_service import FileService
from app.core.database.service.folder_service import FolderService
from app.core.database.service.gc_service import GarbageCollector
from app.core.database.service.wal_service import WalService
from app.core.fuse.temp_store import TempStore
from app.core.runtime_layout import fuse_mounts_dir
from app.utils.logging import logger

from .models import MountInfo
from .mount import MountMixin
from .recovery import RecoveryMixin
from .unmount import UnmountMixin


_RUNTIME_EXPORTS = (json, shutil, subprocess, fuse)


class FuseOrchestrator(RecoveryMixin, MountMixin, UnmountMixin):
    def __init__(
        self,
        cache_dir: Path,
        vault_path: Path,
        db_session: Session,
        key_service: KeyService,
        vault_id: bytes,
        master_key: SecureMemory | bytes,
        auto_recover: bool = True,
    ):
        if platform.system() != "Windows":
            raise OSError("GlyphWeave FUSE mounts are only supported on Windows")

        self.cache_dir = Path(cache_dir)
        self.vault_path = Path(vault_path)
        self.key_service = key_service
        self.vault_id = vault_id
        self.master_key = master_key

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.mount_base = fuse_mounts_dir(self.cache_dir)

        engine = db_session.bind
        self._session_factory = sessionmaker(
            bind=engine,
            autoflush=False,
            autocommit=False,
        )
        try:
            db_session.close()
        except Exception as e:
            logger.debug(f"Failed to close bootstrap DB session: {e}")

        self.temp_store = TempStore(
            cache_dir=self.cache_dir,
            key_service=key_service,
        )
        self.wal_service = WalService(
            session_factory=self._session_factory,
            temp_store=self.temp_store,
        )
        self.file_service = FileService(self._session_factory)
        self.folder_service = FolderService(self._session_factory, self.vault_path)
        self.gc = GarbageCollector(self._session_factory, self.vault_path)

        self._mounts: Dict[int, MountInfo] = {}
        self._lock = threading.Lock()

        if auto_recover:
            self._check_and_recover()


__all__ = ["FuseOrchestrator", "MountInfo"]
