from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from app.core.fuse.types import FileMeta
from app.utils.logging import logger


@dataclass
class FileHandle:
    fh: int
    file_id: str
    path: str
    metadata: FileMeta
    chunk_size: int
    flags: int = 0

    _chunks_cache: OrderedDict = field(default_factory=OrderedDict)
    _dirty_chunks: Set[int] = field(default_factory=set)
    _metadata_dirty: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock)
    max_cache_chunks: int = 64

    opened_at: float = field(default_factory=time.time)
    last_read_at: float = field(default_factory=time.time)
    last_write_at: float = 0.0
    bytes_read: int = 0
    bytes_written: int = 0

    def __post_init__(self):
        if not isinstance(self._chunks_cache, OrderedDict):
            self._chunks_cache = OrderedDict()
        if not isinstance(self._dirty_chunks, set):
            self._dirty_chunks = set()

    @property
    def is_dirty(self) -> bool:
        """Return True if any chunks or metadata have pending unsaved changes."""
        return len(self._dirty_chunks) > 0 or self._metadata_dirty

    @property
    def dirty_chunk_indices(self) -> List[int]:
        """Return the list of chunk indices that have been modified but not flushed."""
        return list(self._dirty_chunks)

    @property
    def cached_chunk_count(self) -> int:
        """Return the number of chunks currently held in the in-memory cache."""
        return len(self._chunks_cache)

    @property
    def cache_size_bytes(self) -> int:
        """Return the total number of bytes occupied by all cached chunks."""
        total = 0
        for chunk in self._chunks_cache.values():
            total += len(chunk) if chunk else 0
        return total

    def get_chunk(self, chunk_index: int) -> Optional[bytearray]:
        """Return the cached bytearray for a chunk, or None if not cached."""
        with self._lock:
            if chunk_index in self._chunks_cache:
                self._chunks_cache.move_to_end(chunk_index)
                self.last_read_at = time.time()
                return self._chunks_cache[chunk_index]
            return None

    def put_chunk(
        self,
        chunk_index: int,
        data: bytes,
        mark_dirty: bool = False,
    ) -> Optional[tuple[int, bytearray, bool]]:
        """Insert or update a chunk in the cache, evicting the oldest clean chunk if
        full."""
        evicted = None
        with self._lock:
            if (
                chunk_index not in self._chunks_cache
                and len(self._chunks_cache) >= self.max_cache_chunks
            ):
                evict_idx = None
                for idx in self._chunks_cache.keys():
                    if idx not in self._dirty_chunks:
                        evict_idx = idx
                        break
                if evict_idx is None:
                    evict_idx = next(iter(self._chunks_cache))
                    logger.warning(
                        f"Evicting dirty chunk {evict_idx} from file {self.file_id}"
                    )

                was_dirty = evict_idx in self._dirty_chunks
                evicted_data = self._chunks_cache.pop(evict_idx)
                self._dirty_chunks.discard(evict_idx)
                evicted = (evict_idx, evicted_data, was_dirty)

            self._chunks_cache[chunk_index] = bytearray(data)
            self._chunks_cache.move_to_end(chunk_index)

            if mark_dirty:
                self._dirty_chunks.add(chunk_index)
                self.last_write_at = time.time()

        return evicted

    def mark_dirty(self, chunk_index: int) -> None:
        """Mark a cached chunk as modified and update the last-write timestamp."""
        with self._lock:
            if chunk_index in self._chunks_cache:
                self._dirty_chunks.add(chunk_index)
                self.last_write_at = time.time()

    def mark_clean(self, chunk_index: int) -> None:
        """Remove a chunk from the dirty set after it has been successfully flushed."""
        with self._lock:
            self._dirty_chunks.discard(chunk_index)

    def mark_all_clean(self) -> None:
        """Clear all dirty chunk and metadata flags after a full flush."""
        with self._lock:
            self._dirty_chunks.clear()
            self._metadata_dirty = False

    def get_dirty_chunks(self) -> Dict[int, bytearray]:
        """Return a snapshot copy of all dirty cached chunks keyed by chunk index."""
        with self._lock:
            return {
                idx: bytearray(self._chunks_cache[idx])
                for idx in self._dirty_chunks
                if idx in self._chunks_cache
            }

    def update_size(self, new_size: int) -> None:
        """Update the tracked plaintext size and refresh the modified timestamp."""
        self.metadata.plaintext_size = new_size
        self.metadata.modified_at = time.time()

    def invalidate_chunks_after(self, chunk_index: int) -> List[int]:
        """Evict all cached chunks with an index greater than chunk_index and return
        their indices."""
        removed = []
        with self._lock:
            to_remove = [idx for idx in self._chunks_cache if idx > chunk_index]
            for idx in to_remove:
                self._secure_clear_chunk(self._chunks_cache.pop(idx))
                self._dirty_chunks.discard(idx)
                removed.append(idx)
        return removed

    def clear_cache(self) -> None:
        """Zero and discard all cached chunks and reset dirty tracking."""
        with self._lock:
            for chunk in self._chunks_cache.values():
                self._secure_clear_chunk(chunk)
            self._chunks_cache.clear()
            self._dirty_chunks.clear()
            self._metadata_dirty = False

    @staticmethod
    def _secure_clear_chunk(chunk: bytearray) -> None:
        """Overwrite all bytes in a bytearray with zeros to reduce key material
        exposure."""
        if chunk and isinstance(chunk, bytearray):
            for i in range(len(chunk)):
                chunk[i] = 0
