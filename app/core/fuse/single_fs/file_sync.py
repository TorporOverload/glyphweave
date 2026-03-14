import time

from app.core.fuse.types import FileMeta


def read_full_file(fs) -> bytes:
    """Read and assemble all chunks of the main file into a single bytes object."""
    size = fs.metadata.plaintext_size
    if size <= 0:
        return b""

    num_chunks = (size + fs.chunk_size - 1) // fs.chunk_size
    data = bytearray()
    for chunk_idx in range(num_chunks):
        chunk = fs.chunk_store.read_chunk(fs.file_id, chunk_idx)
        if chunk is None:
            remaining = min(fs.chunk_size, size - chunk_idx * fs.chunk_size)
            chunk = b"\x00" * remaining
        data.extend(chunk)
    return bytes(data[:size])


def write_full_file(fs, data: bytes) -> None:
    """Chunk and flush the given bytes as the complete new content of the main file."""
    if data is None:
        data = b""

    dirty_chunks = {}
    total_size = len(data)
    if total_size > 0:
        num_chunks = (total_size + fs.chunk_size - 1) // fs.chunk_size
        for chunk_idx in range(num_chunks):
            start = chunk_idx * fs.chunk_size
            end = min(start + fs.chunk_size, total_size)
            dirty_chunks[chunk_idx] = bytearray(data[start:end])

    fs.chunk_store.flush_to_blobs(
        file_id=fs.file_id,
        file_ref_id=fs.file_ref_id,
        dirty_chunks=dirty_chunks,
        original_size=total_size,
    )
    fs._refresh_after_flush()


def refresh_after_flush(fs) -> None:
    """Reload blob index and update all open handles after a flush changes the file
    entry."""
    file_ref = fs.file_service.get_file_reference_with_blobs(fs.file_ref_id)
    if not file_ref or not file_ref.file_entry:
        return

    entry = file_ref.file_entry
    blob_ids = sorted(
        [b.blob_id for b in entry.blobs],
        key=lambda bid: next(b.blob_index for b in entry.blobs if b.blob_id == bid),
    )

    fs.file_id = entry.file_id
    fs.metadata.plaintext_size = entry.original_size_bytes
    fs.metadata.modified_at = time.time()

    fs.chunk_store.load_blob_index(fs.file_id, blob_ids)

    for handle in fs.handle_manager.get_by_path(f"/{fs.file_name}"):
        handle.clear_cache()
        handle.file_id = fs.file_id
        handle.metadata.plaintext_size = fs.metadata.plaintext_size


def open_main(fs, flags: int) -> int:
    """Allocate a new handle for the main file and return its file handle integer."""
    handle = fs.handle_manager.allocate(
        file_id=fs.file_id,
        path=f"/{fs.file_name}",
        metadata=FileMeta(
            file_id=fs.file_id,
            original_name=fs.file_name,
            plaintext_size=fs.metadata.plaintext_size,
            mode=fs.metadata.mode,
            created_at=fs.metadata.created_at,
            modified_at=fs.metadata.modified_at,
            accessed_at=fs.metadata.accessed_at,
        ),
        flags=flags,
    )
    fs._open_count += 1
    return handle.fh
