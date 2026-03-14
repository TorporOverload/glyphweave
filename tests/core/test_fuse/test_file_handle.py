import threading

from app.core.fuse.file_handle import FileHandleManager
from app.core.fuse.types import FileMeta


class _DummyChunkStore:
    def __init__(self):
        self.writes = []

    def read_chunk(self, file_id: str, chunk_index: int):
        return None

    def write_chunk(self, file_id: str, chunk_index: int, data: bytes) -> None:
        self.writes.append((file_id, chunk_index, data))

    def write_metadata(self, file_id: str, metadata: FileMeta) -> None:
        return None

    def truncate_chunks(self, file_id: str, new_size: int) -> None:
        return None


def _make_handle(manager: FileHandleManager):
    return manager.allocate(
        file_id="file-1",
        path="/file.txt",
        metadata=FileMeta(file_id="file-1", original_name="file.txt", plaintext_size=0),
    )


def test_write_chunk_flushes_evicted_dirty_chunk():
    store = _DummyChunkStore()
    manager = FileHandleManager(chunk_store=store, chunk_size=4)
    handle = _make_handle(manager)
    handle.max_cache_chunks = 1

    assert manager.write_chunk(handle.fh, 0, b"aaaa")
    assert manager.write_chunk(handle.fh, 1, b"bbbb")

    assert ("file-1", 0, b"aaaa") in store.writes


def test_global_cache_enforcement_does_not_deadlock_on_dirty_flush():
    store = _DummyChunkStore()
    manager = FileHandleManager(chunk_store=store, chunk_size=4)
    handle = _make_handle(manager)

    assert manager.write_chunk(handle.fh, 0, b"aaaa")
    manager.max_total_cache_bytes = 1

    worker = threading.Thread(target=manager._enforce_global_cache_limit, daemon=True)
    worker.start()
    worker.join(timeout=1.0)

    assert not worker.is_alive()
