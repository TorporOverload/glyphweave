"""Concurrency tests for FileHandleManager - handle allocation, release, and concurrent access."""

import pytest
import threading

from app.infrastructure.fuse.file_handle import FileHandleManager
from app.infrastructure.fuse.types import FileMeta


class _DummyChunkStore:
    """In-memory chunk store for unit testing."""

    def __init__(self):
        self.writes = []
        self.chunks = {}
        self.metadata_writes = []
        self.truncates = []
        self._lock = threading.Lock()

    def read_chunk(self, file_id: str, chunk_index: int):
        return self.chunks.get((file_id, chunk_index))

    def write_chunk(self, file_id: str, chunk_index: int, data: bytes) -> None:
        with self._lock:
            self.writes.append((file_id, chunk_index, data))
            self.chunks[(file_id, chunk_index)] = data

    def write_metadata(self, file_id: str, metadata: FileMeta) -> None:
        self.metadata_writes.append((file_id, metadata))

    def truncate_chunks(self, file_id: str, new_size: int) -> None:
        with self._lock:
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


class TestMultipleHandlesSamePath:
    """Tests for multiple handles on the same path."""

    def test_multiple_handles_same_path_increments_total_opens(self):
        manager, _ = _make_manager()
        h1 = _alloc(manager, path="/same.txt")
        h2 = _alloc(manager, path="/same.txt")

        assert manager.total_opens == 2
        assert manager.open_handle_count == 2

    def test_get_by_path_returns_all_handles_for_same_path(self):
        manager, _ = _make_manager()
        h1 = _alloc(manager, path="/same.txt")
        h2 = _alloc(manager, path="/same.txt")
        h3 = _alloc(manager, path="/same.txt")

        handles = manager.get_by_path("/same.txt")
        assert len(handles) == 3
        assert set(h.fh for h in handles) == {h1.fh, h2.fh, h3.fh}

    def test_release_one_handle_keeps_others_on_same_path(self):
        manager, _ = _make_manager()
        h1 = _alloc(manager, path="/same.txt")
        h2 = _alloc(manager, path="/same.txt")

        released = manager.release(h1.fh)
        assert released is h1
        assert manager.open_handle_count == 1

        remaining = manager.get_by_path("/same.txt")
        assert len(remaining) == 1
        assert remaining[0].fh == h2.fh

    def test_release_all_handles_clears_path(self):
        manager, _ = _make_manager()
        h1 = _alloc(manager, path="/same.txt")
        h2 = _alloc(manager, path="/same.txt")

        manager.release(h1.fh)
        manager.release(h2.fh)

        assert manager.get_by_path("/same.txt") == []
        assert manager.open_handle_count == 0

    def test_handles_have_unique_fh_values(self):
        manager, _ = _make_manager()
        handles = [_alloc(manager, file_id=f"f{i}", path=f"/f{i}.txt") for i in range(5)]
        fh_values = [h.fh for h in handles]
        assert len(fh_values) == len(set(fh_values)), "All handle IDs must be unique"


class TestHandleAllocationUniqueness:
    """Tests for handle ID uniqueness and allocation."""

    def test_fh_values_never_repeat_after_release(self):
        manager, _ = _make_manager()
        h1 = _alloc(manager, file_id="f1", path="/a.txt")
        first_fh = h1.fh
        manager.release(h1.fh)

        h2 = _alloc(manager, file_id="f2", path="/b.txt")
        assert h2.fh != first_fh

    def test_allocate_after_release_reuses_nothing(self):
        manager, _ = _make_manager()
        h1 = _alloc(manager, file_id="f1", path="/a.txt")
        fh1 = h1.fh
        manager.release(h1.fh)

        h2 = _alloc(manager, file_id="f2", path="/b.txt")
        assert h2.fh != fh1
        assert manager.get(fh1) is None
        assert manager.get(h2.fh) is h2


class TestHandleOverflow:
    """Tests for handle overflow beyond max_handles."""

    def test_after_release_can_allocate_again(self):
        manager, _ = _make_manager(max_handles=2)
        h1 = _alloc(manager, file_id="f1", path="/a.txt")
        h2 = _alloc(manager, file_id="f2", path="/b.txt")
        manager.release(h1.fh)

        h3 = _alloc(manager, file_id="f3", path="/c.txt")
        assert h3 is not None
        assert manager.open_handle_count == 2

    def test_max_handles_respected_after_partial_release(self):
        manager, _ = _make_manager(max_handles=2)
        h1 = _alloc(manager, file_id="f1", path="/a.txt")
        h2 = _alloc(manager, file_id="f2", path="/b.txt")
        assert manager.open_handle_count == 2

        manager.release(h1.fh)
        assert manager.open_handle_count == 1

        h3 = _alloc(manager, file_id="f3", path="/c.txt")
        assert h3 is not None
        assert manager.open_handle_count == 2

        with pytest.raises(OSError, match="Too many open files"):
            _alloc(manager, file_id="f-extra", path="/extra.txt")


class TestConcurrentReadWrite:
    """Tests for concurrent read/write to different handles."""

    def test_concurrent_write_to_different_handles(self):
        manager, store = _make_manager(chunk_size=4)
        h1 = _alloc(manager, file_id="f1", path="/a.txt")
        h2 = _alloc(manager, file_id="f2", path="/b.txt")

        results = []

        def write_to_handle(handle, data):
            manager.write_chunk(handle.fh, 0, data)
            results.append((handle.fh, data))

        t1 = threading.Thread(target=write_to_handle, args=(h1, b"aaaa"))
        t2 = threading.Thread(target=write_to_handle, args=(h2, b"bbbb"))

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert h1.is_dirty
        assert h2.is_dirty
        assert len(results) == 2

    def test_concurrent_read_from_different_handles(self):
        manager, store = _make_manager(chunk_size=4)
        store.chunks[("f1", 0)] = b"aaaa"
        store.chunks[("f2", 0)] = b"bbbb"

        h1 = _alloc(manager, file_id="f1", path="/a.txt")
        h2 = _alloc(manager, file_id="f2", path="/b.txt")

        results = []

        def read_from_handle(handle, expected):
            data = manager.read_chunk(handle.fh, 0)
            results.append((handle.fh, data))
            assert data == expected

        t1 = threading.Thread(target=read_from_handle, args=(h1, b"aaaa"))
        t2 = threading.Thread(target=read_from_handle, args=(h2, b"bbbb"))

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(results) == 2

    def test_concurrent_read_write_different_handles(self):
        manager, store = _make_manager(chunk_size=4)
        store.chunks[("f1", 0)] = b"aaaa"

        h1 = _alloc(manager, file_id="f1", path="/a.txt")
        h2 = _alloc(manager, file_id="f2", path="/b.txt")

        read_result = []
        write_result = []

        def read_op():
            data = manager.read_chunk(h1.fh, 0)
            read_result.append(data)

        def write_op():
            manager.write_chunk(h2.fh, 0, b"cccc")
            write_result.append(True)

        t1 = threading.Thread(target=read_op)
        t2 = threading.Thread(target=write_op)

        t2.start()
        t1.start()
        t1.join()
        t2.join()

        assert read_result[0] == b"aaaa"
        assert write_result[0] is True
        assert h2.is_dirty


class TestReleaseWithMultipleHandles:
    """Tests for release behavior with multiple handles on same path."""

    def test_release_clears_only_released_handle(self):
        manager, _ = _make_manager(chunk_size=4)
        h1 = _alloc(manager, path="/same.txt")
        h2 = _alloc(manager, path="/same.txt")

        manager.write_chunk(h1.fh, 0, b"aaaa")
        manager.write_chunk(h2.fh, 0, b"bbbb")

        manager.release(h1.fh, flush=False)

        assert manager.get(h1.fh) is None
        assert manager.get(h2.fh) is h2
        assert h2.is_dirty

    def test_release_with_flush_writes_only_released_handle(self):
        manager, store = _make_manager(chunk_size=4)
        h1 = _alloc(manager, file_id="f1", path="/same.txt")
        h2 = _alloc(manager, file_id="f2", path="/same.txt")

        manager.write_chunk(h1.fh, 0, b"aaaa")
        manager.write_chunk(h2.fh, 0, b"bbbb")

        manager.release(h1.fh, flush=True)

        assert ("f1", 0, b"aaaa") in store.writes
        assert ("f2", 0, b"bbbb") not in store.writes

    def test_release_multiple_handles_different_paths(self):
        manager, store = _make_manager(chunk_size=4)
        h1 = _alloc(manager, file_id="f1", path="/a.txt")
        h2 = _alloc(manager, file_id="f2", path="/b.txt")

        manager.write_chunk(h1.fh, 0, b"aaaa")
        manager.write_chunk(h2.fh, 0, b"bbbb")

        manager.release(h1.fh)
        manager.release(h2.fh)

        assert manager.open_handle_count == 0
        assert ("f1", 0, b"aaaa") in store.writes
        assert ("f2", 0, b"bbbb") in store.writes


class TestConcurrencyStats:
    """Tests for stats accuracy with concurrent operations."""

    def test_total_opens_after_concurrent_allocations(self):
        manager, _ = _make_manager()

        def alloc_and_release():
            h = _alloc(manager, file_id=threading.current_thread().name, path=f"/{threading.current_thread().name}.txt")
            return h.fh

        threads = [threading.Thread(target=alloc_and_release) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert manager.total_opens == 5
        assert manager.open_handle_count == 5