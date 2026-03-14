"""Single-file FUSE filesystem public API."""

import unicodedata
import stat
from pathlib import Path
from typing import List

from mfusepy import Operations
from sqlalchemy.orm import Session, sessionmaker

from app.core.crypto.constants import FUSE_CHUNK_SIZE
from app.core.crypto.service.key_service import KeyService
from app.core.database.service.file_service import FileService
from app.core.database.service.folder_service import FolderService
from app.core.database.service.gc_service import GarbageCollector
from app.core.database.service.wal_service import WalService
from app.core.fuse.chunk_store import ChunkStore
from app.core.fuse.file_handle import FileHandleManager
from app.core.fuse.temp_store import TempStore
from app.core.fuse.types import FileMeta

from .file_sync import open_main, read_full_file, refresh_after_flush, write_full_file
from .lifecycle_ops import destroy_fs, flush_file, fsync_file, statfs
from .main_ops import (
    getattr_op,
    open_op,
    read_op,
    readdir_op,
    release_op,
    truncate_op,
    write_op,
)
from .temp_ops import (
    access_op,
    chmod_op,
    chown_op,
    create_op,
    mkdir_op,
    rename_op,
    unlink_op,
    utimens_op,
)


class SingleFileFS(Operations):
    def __init__(
        self,
        file_name: str,
        file_id: str,
        file_ref_id: int,
        plaintext_size: int,
        blob_ids: List[str],
        vault_path: Path,
        cache_dir: Path,
        mount_dir: Path,
        key_service: KeyService,
        vault_id: bytes,
        db_session: Session,
        master_key: bytes | None = None,
        chunk_size: int = FUSE_CHUNK_SIZE,
    ):
        self.file_name = file_name
        self._main_name_key = self._normalize_name(file_name)
        self.file_id = file_id
        self.file_ref_id = file_ref_id
        self.vault_path = vault_path
        self.cache_dir = cache_dir
        self.mount_dir = mount_dir
        self.key_service = key_service
        self.vault_id = vault_id
        self.master_key = master_key
        self.chunk_size = chunk_size
        self._open_count = 0

        self._temp_files = {}
        self._temp_meta = {}
        self._temp_file_handles = {}
        self._temp_fh_counter = 10_000

        self.metadata = FileMeta(
            file_id=file_id,
            original_name=file_name,
            plaintext_size=plaintext_size,
            mode=stat.S_IFREG | 0o777,
        )

        engine = db_session.bind
        self._session_factory = sessionmaker(
            bind=engine, autoflush=False, autocommit=False
        )
        self.file_service = FileService(self._session_factory)
        self.folder_service = FolderService(self._session_factory, vault_path)
        self.gc = GarbageCollector(self._session_factory, vault_path)

        self.chunk_store = ChunkStore(
            vault_path=vault_path,
            cache_dir=cache_dir,
            key_service=key_service,
            vault_id=vault_id,
            file_service=self.file_service,
            folder_service=self.folder_service,
            gc=self.gc,
            chunk_size=chunk_size,
        )

        self.temp_store = TempStore(
            cache_dir=cache_dir,
            key_service=key_service,
        )
        self.wal_service = WalService(
            session_factory=self._session_factory,
            temp_store=self.temp_store,
        )

        self.handle_manager = FileHandleManager(
            chunk_store=self.chunk_store,
            chunk_size=chunk_size,
            on_chunk_write=self._on_chunk_write,
        )
        self.chunk_store.load_blob_index(file_id, blob_ids)

    @staticmethod
    def _normalize_name(name: str) -> str:
        normalized = unicodedata.normalize("NFKC", name)
        normalized = normalized.replace("\u2018", "'").replace("\u2019", "'")
        normalized = normalized.replace("\u201c", '"').replace("\u201d", '"')
        return normalized.casefold()

    def _is_main_path(self, path: str) -> bool:
        if path == f"/{self.file_name}":
            return True
        if path == "/":
            return False
        return self._normalize_name(path.lstrip("/")) == self._main_name_key

    def _on_chunk_write(self, file_id: str, path: str, chunk_index: int, data: bytes):
        self.wal_service.log_write(
            file_ref_id=self.file_ref_id,
            chunk_index=chunk_index,
            offset=chunk_index * self.chunk_size,
            length=len(data),
            data=data,
            file_id=file_id,
        )

    def getattr(self, path, fh=None):
        return getattr_op(self, path, fh)

    def readdir(self, path, fh):
        return readdir_op(self, path, fh)

    def open(self, path, flags):
        return open_op(self, path, flags)

    def read(self, path, size, offset, fh):
        return read_op(self, path, size, offset, fh)

    def write(self, path, data, offset, fh):
        return write_op(self, path, data, offset, fh)

    def truncate(self, path, length, fh=None):
        return truncate_op(self, path, length, fh)

    def release(self, path, fh):
        return release_op(self, path, fh)

    def flush(self, path, fh):
        return flush_file(self, path, fh)

    def fsync(self, path, datasync, fh):
        return fsync_file(self, path, datasync, fh)

    def create(self, path, mode, fi=None):
        return create_op(self, path, mode, fi)

    def unlink(self, path):
        return unlink_op(self, path)

    def mkdir(self, path, mode):
        return mkdir_op(self, path, mode)

    def chmod(self, path, mode):
        return chmod_op(self, path, mode)

    def chown(self, path, uid, gid):
        return chown_op(self, path, uid, gid)

    def utimens(self, path, times=None):
        return utimens_op(self, path, times)

    def access(self, path, amode):
        return access_op(self, path, amode)

    def statfs(self, path):
        return statfs(self, path)

    def destroy(self, path):
        return destroy_fs(self, path)

    def rename(self, old, new):
        return rename_op(self, old, new)

    def _read_full_file(self) -> bytes:
        return read_full_file(self)

    def _write_full_file(self, data: bytes) -> None:
        return write_full_file(self, data)

    def _refresh_after_flush(self) -> None:
        return refresh_after_flush(self)

    def _open_main(self, flags: int) -> int:
        return open_main(self, flags)


__all__ = ["SingleFileFS"]
