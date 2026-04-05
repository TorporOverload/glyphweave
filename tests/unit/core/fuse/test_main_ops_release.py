from __future__ import annotations

from types import SimpleNamespace

from app.infrastructure.fuse.single_fs.main_ops import release_op


class _Handle:
    def __init__(self) -> None:
        self.is_dirty = True
        self.metadata = SimpleNamespace(plaintext_size=12)

    def get_dirty_chunks(self):
        return {0: bytearray(b"updated data")}


class _HandleManager:
    def __init__(self, handle) -> None:
        self._handle = handle
        self.released = False

    def get(self, fh):
        return self._handle if fh == 1 else None

    def release(self, fh, flush=False):
        assert fh == 1
        assert flush is False
        self.released = True


class _EventEmitter:
    def __init__(self) -> None:
        self.calls = []

    def emit_file_update(self, updated_ref, old_entry, new_entry):
        self.calls.append((updated_ref, old_entry, new_entry))


def test_release_op_emits_file_update_after_successful_flush() -> None:
    old_entry = SimpleNamespace(file_id="old-file", content_hash="old-hash")
    new_entry = SimpleNamespace(file_id="new-file", content_hash="new-hash")
    old_ref = SimpleNamespace(file_entry=old_entry)
    updated_ref = SimpleNamespace(file_entry=new_entry)
    handle = _Handle()
    emitter = _EventEmitter()
    file_service_calls = []

    def _get_file_reference_with_blobs(file_ref_id):
        file_service_calls.append(file_ref_id)
        return old_ref if len(file_service_calls) == 1 else updated_ref

    fs = SimpleNamespace(
        _temp_file_handles={},
        handle_manager=_HandleManager(handle),
        file_id="old-file",
        file_ref_id=42,
        chunk_store=SimpleNamespace(
            flush_to_blobs=lambda **kwargs: None,
        ),
        _refresh_after_flush=lambda: None,
        wal_service=SimpleNamespace(
            get_pending_entries=lambda file_ref_id: [],
            mark_flushed=lambda ids: None,
            checkpoint=lambda file_ref_id: 0,
        ),
        _open_count=1,
        file_service=SimpleNamespace(
            get_file_reference_with_blobs=_get_file_reference_with_blobs
        ),
        event_emitter=emitter,
    )

    result = release_op(fs, "/report.txt", 1)

    assert result == 0
    assert fs.handle_manager.released is True
    assert fs._open_count == 0
    assert file_service_calls == [42, 42]
    assert len(emitter.calls) == 1
    assert emitter.calls[0] == (updated_ref, old_entry, new_entry)


def test_release_op_skips_emit_when_file_entry_is_unchanged() -> None:
    shared_entry = SimpleNamespace(file_id="same-file", content_hash="same-hash")
    shared_ref = SimpleNamespace(file_entry=shared_entry)
    handle = _Handle()
    emitter = _EventEmitter()

    fs = SimpleNamespace(
        _temp_file_handles={},
        handle_manager=_HandleManager(handle),
        file_id="same-file",
        file_ref_id=7,
        chunk_store=SimpleNamespace(
            flush_to_blobs=lambda **kwargs: None,
        ),
        _refresh_after_flush=lambda: None,
        wal_service=SimpleNamespace(
            get_pending_entries=lambda file_ref_id: [],
            mark_flushed=lambda ids: None,
            checkpoint=lambda file_ref_id: 0,
        ),
        _open_count=1,
        file_service=SimpleNamespace(
            get_file_reference_with_blobs=lambda file_ref_id: shared_ref
        ),
        event_emitter=emitter,
    )

    result = release_op(fs, "/report.txt", 1)

    assert result == 0
    assert emitter.calls == []
