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

from . import mount, probes, recovery, unmount
from .models import MountInfo


_RUNTIME_EXPORTS = (json, shutil, subprocess, fuse)


class FuseOrchestrator:
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

    @staticmethod
    def _mount_file_name(
        original_name: str,
        file_ref_id: int,
        mount_dir: Path,
        mime_type: str | None = None,
    ) -> str:
        return probes.mount_file_name(original_name, file_ref_id, mount_dir, mime_type)

    def _wait_for_mount_path(self, file_path: Path, timeout: float) -> bool:
        return probes.wait_for_mount_path(file_path, timeout)

    def _wait_for_mount_ready(self, file_path: Path, timeout: float) -> None:
        probes.wait_for_mount_ready(file_path, timeout)

    def _wait_for_mount_responsive(self, file_path: Path, timeout: float) -> bool:
        return probes.wait_for_mount_responsive(file_path, timeout)

    def _wait_for_mount_office_ready(
        self,
        mount_dir: Path,
        file_path: Path,
        timeout: float,
    ) -> bool:
        return probes.wait_for_mount_office_ready(mount_dir, file_path, timeout)

    def _check_and_recover(self) -> None:
        recovery.check_and_recover(self)

    def _replay_entries_for_file(self, file_ref_id: int, entries) -> None:
        recovery.replay_entries_for_file(self, file_ref_id, entries)

    def _open_in_default_app(self, file_path) -> None:
        mount.open_in_default_app(self, file_path)

    def _master_key_hex(self) -> str:
        return mount.master_key_hex(self)

    def mount_and_open(
        self,
        file_ref_id: int,
        open_in_app: bool = True,
    ):
        return mount.mount_and_open(self, file_ref_id, open_in_app)

    def is_mounted(self, file_ref_id: int) -> bool:
        return unmount.is_mounted(self, file_ref_id)

    def get_mounted_path(self, file_ref_id: int):
        return unmount.get_mounted_path(self, file_ref_id)

    @property
    def active_mount_count(self) -> int:
        return unmount.active_mount_count(self)

    def get_active_mounts(self):
        return unmount.get_active_mounts(self)

    def unmount(self, file_ref_id: int, background: bool = False) -> bool:
        return unmount.unmount(self, file_ref_id, background)

    def _unmount_info(self, file_ref_id: int, info: MountInfo) -> None:
        unmount.unmount_info(self, file_ref_id, info)

    def _wait_for_handles_to_close(self, info: MountInfo, timeout: float) -> None:
        unmount.wait_for_handles_to_close(info, timeout)

    def cleanup_all(self) -> int:
        return unmount.cleanup_all(self)


__all__ = ["FuseOrchestrator", "MountInfo"]
