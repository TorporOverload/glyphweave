from __future__ import annotations

import threading
from typing import Dict, List, Optional, Set

from app.core.fuse.types import FileMeta
from app.utils.logging import logger

from .cache_policy import enforce_global_cache_limit
from .handle import FileHandle
from .io import flush_all, flush_handle, read_chunk, truncate, write_chunk
from .types import ChunkStoreProtocol, OnChunkWriteCallback


class FileHandleManager:
    def __init__(
        self,
        chunk_store: ChunkStoreProtocol,
        chunk_size: int = 64 * 1024,
        max_total_cache_mb: int = 256,
        max_handles: int = 1024,
        on_chunk_write: Optional[OnChunkWriteCallback] = None,
    ):
        self.chunk_store = chunk_store
        self.chunk_size = chunk_size
        self.max_total_cache_bytes = max_total_cache_mb * 1024 * 1024
        self.max_handles = max_handles
        self._on_chunk_write = on_chunk_write

        self._handles: Dict[int, FileHandle] = {}
        self._path_to_fh: Dict[str, Set[int]] = {}
        self._lock = threading.Lock()
        self._next_fh = 1

        self.total_opens = 0
        self.total_closes = 0
        self.total_flushes = 0

    @property
    def open_handle_count(self) -> int:
        """Return the number of currently open file handles."""
        return len(self._handles)

    @property
    def total_cache_bytes(self) -> int:
        """Return the combined in-memory cache size across all open handles."""
        total = 0
        with self._lock:
            for handle in self._handles.values():
                total += handle.cache_size_bytes
        return total

    def allocate(
        self,
        file_id: str,
        path: str,
        metadata: FileMeta,
        flags: int = 0,
    ) -> FileHandle:
        """Create and register a new FileHandle, raising OSError if the handle limit is
        reached."""
        with self._lock:
            if len(self._handles) >= self.max_handles:
                raise OSError(f"Too many open files (max: {self.max_handles})")

            fh = self._next_fh
            self._next_fh += 1

            handle = FileHandle(
                fh=fh,
                file_id=file_id,
                path=path,
                metadata=metadata,
                chunk_size=self.chunk_size,
                flags=flags,
            )

            self._handles[fh] = handle
            if path not in self._path_to_fh:
                self._path_to_fh[path] = set()
            self._path_to_fh[path].add(fh)
            self.total_opens += 1

        logger.debug(f"Allocated handle {fh} for {path} (file_id={file_id})")
        return handle

    def get(self, fh: int) -> Optional[FileHandle]:
        """Return the FileHandle for fh, or None if not found."""
        with self._lock:
            return self._handles.get(fh)

    def get_by_path(self, path: str) -> List[FileHandle]:
        """Return all open FileHandles associated with the given path."""
        with self._lock:
            fh_set = self._path_to_fh.get(path, set())
            return [self._handles[fh] for fh in fh_set if fh in self._handles]

    def release(self, fh: int, flush: bool = True) -> Optional[FileHandle]:
        """Flush, deregister, and clear cache for a handle; return it or None if
        absent."""
        handle = self.get(fh)
        if not handle:
            return None

        if flush and handle.is_dirty:
            self.flush_handle(fh)

        with self._lock:
            self._handles.pop(fh, None)
            if handle.path in self._path_to_fh:
                self._path_to_fh[handle.path].discard(fh)
                if not self._path_to_fh[handle.path]:
                    del self._path_to_fh[handle.path]
            self.total_closes += 1

        handle.clear_cache()
        logger.debug(
            f"Released handle {fh} for {handle.path} "
            f"(read: {handle.bytes_read}, written: {handle.bytes_written})"
        )
        return handle

    def read_chunk(self, fh: int, chunk_index: int, load_from_disk: bool = True):
        """Read a chunk for fh from cache or blob storage."""
        return read_chunk(self, fh, chunk_index, load_from_disk=load_from_disk)

    def write_chunk(
        self,
        fh: int,
        chunk_index: int,
        data: bytes,
        write_through: bool = False,
    ) -> bool:
        """Write a chunk for fh into the cache, optionally flushing immediately."""
        return write_chunk(
            self,
            fh,
            chunk_index,
            data,
            write_through=write_through,
        )

    def flush_handle(self, fh: int) -> bool:
        """Flush all dirty chunks for the handle identified by fh."""
        return flush_handle(self, fh)

    def flush_all(self) -> int:
        """Flush every dirty open handle and return the count flushed."""
        return flush_all(self)

    def _flush_single_chunk(
        self, handle: FileHandle, chunk_index: int, data: bytes
    ) -> None:
        """Write a single chunk directly to the chunk store without cache
        bookkeeping."""
        self.chunk_store.write_chunk(handle.file_id, chunk_index, data)

    def _enforce_global_cache_limit(self) -> None:
        """Trigger cache eviction if total cached bytes exceed the configured limit."""
        enforce_global_cache_limit(self)

    def truncate(self, fh: int, new_size: int) -> bool:
        """Truncate the file for fh to new_size bytes."""
        return truncate(self, fh, new_size)

    def get_stats(self) -> Dict:
        """Return a snapshot of handle manager statistics including cache and flush
        counts."""
        with self._lock:
            dirty_handles = sum(1 for h in self._handles.values() if h.is_dirty)
            total_dirty_chunks = sum(
                len(h._dirty_chunks) for h in self._handles.values()
            )

        return {
            "open_handles": self.open_handle_count,
            "dirty_handles": dirty_handles,
            "total_dirty_chunks": total_dirty_chunks,
            "total_cache_bytes": self.total_cache_bytes,
            "max_cache_bytes": self.max_total_cache_bytes,
            "total_opens": self.total_opens,
            "total_closes": self.total_closes,
            "total_flushes": self.total_flushes,
        }

    def close_all(self, flush: bool = True) -> int:
        """Release all open handles, optionally flushing dirty data, and return the
        count closed."""
        with self._lock:
            fh_list = list(self._handles.keys())

        closed = 0
        for fh in fh_list:
            if self.release(fh, flush=flush):
                closed += 1
        return closed
