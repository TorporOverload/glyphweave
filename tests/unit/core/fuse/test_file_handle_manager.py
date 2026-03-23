"""Unit tests for FileHandleManager - handle allocation, caching, flush, truncate."""

import pytest

from app.infrastructure.fuse.file_handle import FileHandleManager
from app.infrastructure.fuse.types import FileMeta


class _DummyChunkStore:
    """In-memory chunk store for unit testing."""

    def __init__(self):
        self.writes = []
        self.chunks = {}  # (file_id, chunk_index) -> bytes
        self.metadata_writes = []
        self.truncates = []

    def read_chunk(self, file_id: str, chunk_index: int):
        return self.chunks.get((file_id, chunk_index))

    def write_chunk(self, file_id: str, chunk_index: int, data: bytes) -> None:
        self.writes.append((file_id, chunk_index, data))
        self.chunks[(file_id, chunk_index)] = data

    def write_metadata(self, file_id: str, metadata: FileMeta) -> None:
        self.metadata_writes.append((file_id, metadata))

    def truncate_chunks(self, file_id: str, new_size: int) -> None:
        self.truncates.append((file_id, new_size))


def _make_manager(chunk_size=64, **kwargs):
    store = _DummyChunkStore()
    manager = FileHandleManager(chunk_store=store, chunk_size=chunk_size, **kwargs)
    return manager, store


def _alloc(manager, file_id="file-1", path="/file.txt", size=0):
    return manager.allocate(
        file_id=file_id,
        path=path,
        metadata=FileMeta(file_id=file_id, original_name="file.txt", plaintext_size=size),
    )


class TestAllocate:
    def test_unique_handles(self):
        manager, _ = _make_manager()
        h1 = _alloc(manager)
        h2 = _alloc(manager, file_id="file-2", path="/file2.txt")
        h3 = _alloc(manager, file_id="file-3", path="/file3.txt")

        assert len({h1.fh, h2.fh, h3.fh}) == 3
        assert manager.open_handle_count == 3

    def test_exceeds_max_handles_raises(self):
        manager, _ = _make_manager(max_handles=2)
        _alloc(manager, file_id="f1", path="/a.txt")
        _alloc(manager, file_id="f2", path="/b.txt")

        with pytest.raises(OSError, match="Too many open files"):
            _alloc(manager, file_id="f3", path="/c.txt")

    def test_increments_total_opens(self):
        manager, _ = _make_manager()
        assert manager.total_opens == 0
        _alloc(manager)
        assert manager.total_opens == 1


class TestGetAndGetByPath:
    def test_get_returns_handle(self):
        manager, _ = _make_manager()
        h = _alloc(manager)
        assert manager.get(h.fh) is h

    def test_get_nonexistent_returns_none(self):
        manager, _ = _make_manager()
        assert manager.get(999) is None

    def test_get_by_path_returns_all(self):
        manager, _ = _make_manager()
        h1 = _alloc(manager)
        h2 = _alloc(manager)  # same path, different handle
        handles = manager.get_by_path("/file.txt")
        assert set(h.fh for h in handles) == {h1.fh, h2.fh}

    def test_get_by_path_empty(self):
        manager, _ = _make_manager()
        assert manager.get_by_path("/nope") == []


class TestRelease:
    def test_release_removes_handle(self):
        manager, _ = _make_manager()
        h = _alloc(manager)
        released = manager.release(h.fh)

        assert released is h
        assert manager.get(h.fh) is None
        assert manager.open_handle_count == 0
        assert manager.total_closes == 1

    def test_release_nonexistent_returns_none(self):
        manager, _ = _make_manager()
        assert manager.release(999) is None

    def test_release_flushes_dirty(self):
        manager, store = _make_manager(chunk_size=4)
        h = _alloc(manager)
        manager.write_chunk(h.fh, 0, b"aaaa")

        manager.release(h.fh, flush=True)
        assert ("file-1", 0, b"aaaa") in store.writes

    def test_release_skip_flush(self):
        manager, store = _make_manager(chunk_size=4)
        h = _alloc(manager)
        manager.write_chunk(h.fh, 0, b"aaaa")

        manager.release(h.fh, flush=False)
        # write_chunk itself writes to store via callback, but flush_handle shouldn't be called
        # The write to store.writes happens from write_chunk's on_chunk_write or eviction,
        # not from flush_handle. Let's check flush count instead.
        assert manager.total_flushes == 0


class TestReadChunk:
    def test_cache_miss_loads_from_store(self):
        manager, store = _make_manager(chunk_size=4)
        store.chunks[("file-1", 0)] = b"abcd"
        h = _alloc(manager)

        data = manager.read_chunk(h.fh, 0)
        assert data == b"abcd"
        assert h.bytes_read == 4

    def test_cache_hit_skips_store(self):
        manager, store = _make_manager(chunk_size=4)
        store.chunks[("file-1", 0)] = b"abcd"
        h = _alloc(manager)

        # First read loads from store
        manager.read_chunk(h.fh, 0)
        initial_read = h.bytes_read

        # Second read should hit cache (bytes_read won't increase again)
        data = manager.read_chunk(h.fh, 0)
        assert data == b"abcd"
        assert h.bytes_read == initial_read  # no additional disk read

    def test_read_nonexistent_chunk(self):
        manager, _ = _make_manager()
        h = _alloc(manager)
        assert manager.read_chunk(h.fh, 99) is None

    def test_read_nonexistent_handle(self):
        manager, _ = _make_manager()
        assert manager.read_chunk(999, 0) is None


class TestWriteChunk:
    def test_marks_dirty(self):
        manager, _ = _make_manager(chunk_size=4)
        h = _alloc(manager)
        assert manager.write_chunk(h.fh, 0, b"aaaa")
        assert h.is_dirty
        assert 0 in h.dirty_chunk_indices

    def test_fires_callback(self):
        calls = []

        def cb(file_id, path, chunk_idx, data):
            calls.append((file_id, path, chunk_idx, data))

        manager = FileHandleManager(
            chunk_store=_DummyChunkStore(),
            chunk_size=4,
            on_chunk_write=cb,
        )
        h = _alloc(manager)
        manager.write_chunk(h.fh, 0, b"aaaa")

        assert len(calls) == 1
        assert calls[0] == ("file-1", "/file.txt", 0, b"aaaa")

    def test_write_nonexistent_handle(self):
        manager, _ = _make_manager()
        assert manager.write_chunk(999, 0, b"data") is False

    def test_updates_bytes_written(self):
        manager, _ = _make_manager(chunk_size=4)
        h = _alloc(manager)
        manager.write_chunk(h.fh, 0, b"abcd")
        assert h.bytes_written == 4


class TestFlush:
    def test_flush_handle_clears_dirty(self):
        manager, store = _make_manager(chunk_size=4)
        h = _alloc(manager)
        manager.write_chunk(h.fh, 0, b"aaaa")
        manager.write_chunk(h.fh, 1, b"bbbb")

        assert manager.flush_handle(h.fh)
        assert not h.is_dirty
        assert manager.total_flushes == 1
        # Both chunks written to store
        assert ("file-1", 0, b"aaaa") in store.writes
        assert ("file-1", 1, b"bbbb") in store.writes

    def test_flush_all_multiple_handles(self):
        manager, store = _make_manager(chunk_size=4)
        h1 = _alloc(manager, file_id="f1", path="/a.txt")
        h2 = _alloc(manager, file_id="f2", path="/b.txt")
        manager.write_chunk(h1.fh, 0, b"aaaa")
        manager.write_chunk(h2.fh, 0, b"bbbb")

        flushed = manager.flush_all()
        assert flushed == 2
        assert not h1.is_dirty
        assert not h2.is_dirty

    def test_flush_nonexistent_handle(self):
        manager, _ = _make_manager()
        assert manager.flush_handle(999) is False

    def test_flush_clean_handle(self):
        manager, _ = _make_manager()
        h = _alloc(manager)
        # No writes, handle is clean
        assert manager.flush_handle(h.fh) is True
        assert manager.total_flushes == 0  # nothing to flush


class TestTruncate:
    def test_truncate_shrinks(self):
        manager, store = _make_manager(chunk_size=4)
        h = _alloc(manager, size=12)
        # Write 3 chunks
        manager.write_chunk(h.fh, 0, b"aaaa")
        manager.write_chunk(h.fh, 1, b"bbbb")
        manager.write_chunk(h.fh, 2, b"cccc")

        assert manager.truncate(h.fh, 6)
        assert h.metadata.plaintext_size == 6
        # Chunk 2 should be evicted (index > 1)
        assert h.get_chunk(2) is None
        assert ("file-1", 6) in store.truncates

    def test_truncate_to_zero(self):
        manager, store = _make_manager(chunk_size=4)
        h = _alloc(manager, size=8)
        manager.write_chunk(h.fh, 0, b"aaaa")
        manager.write_chunk(h.fh, 1, b"bbbb")

        assert manager.truncate(h.fh, 0)
        assert h.metadata.plaintext_size == 0
        assert h.cached_chunk_count == 0

    def test_truncate_nonexistent(self):
        manager, _ = _make_manager()
        assert manager.truncate(999, 0) is False

    def test_truncate_same_size_noop(self):
        manager, store = _make_manager(chunk_size=4)
        h = _alloc(manager, size=8)
        assert manager.truncate(h.fh, 8)
        assert store.truncates == []  # no call to chunk_store


class TestStats:
    def test_get_stats(self):
        manager, _ = _make_manager(chunk_size=4)
        h = _alloc(manager)
        manager.write_chunk(h.fh, 0, b"aaaa")

        stats = manager.get_stats()
        assert stats["open_handles"] == 1
        assert stats["dirty_handles"] == 1
        assert stats["total_dirty_chunks"] == 1
        assert stats["total_cache_bytes"] == 4
        assert stats["total_opens"] == 1
        assert stats["total_closes"] == 0
        assert stats["total_flushes"] == 0


class TestCloseAll:
    def test_close_all(self):
        manager, _ = _make_manager()
        _alloc(manager, file_id="f1", path="/a.txt")
        _alloc(manager, file_id="f2", path="/b.txt")
        _alloc(manager, file_id="f3", path="/c.txt")

        closed = manager.close_all(flush=False)
        assert closed == 3
        assert manager.open_handle_count == 0

    def test_close_all_flushes_dirty(self):
        manager, store = _make_manager(chunk_size=4)
        h = _alloc(manager)
        manager.write_chunk(h.fh, 0, b"aaaa")

        closed = manager.close_all(flush=True)
        assert closed == 1
        assert ("file-1", 0, b"aaaa") in store.writes


class TestTotalCacheBytes:
    def test_matches_chunk_sizes(self):
        manager, _ = _make_manager(chunk_size=4)
        h = _alloc(manager)
        manager.write_chunk(h.fh, 0, b"aaaa")
        manager.write_chunk(h.fh, 1, b"bb")  # smaller chunk

        assert manager.total_cache_bytes == 6
