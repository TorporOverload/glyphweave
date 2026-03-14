from app.utils.logging import logger


def read_chunk(manager, fh: int, chunk_index: int, load_from_disk: bool = True):
    """Return chunk data from cache or decrypt it from blob storage on a cache miss."""
    handle = manager.get(fh)
    if not handle:
        return None

    cached = handle.get_chunk(chunk_index)
    if cached is not None:
        return bytes(cached)

    if not load_from_disk:
        return None

    try:
        data = manager.chunk_store.read_chunk(handle.file_id, chunk_index)
        if data:
            manager._enforce_global_cache_limit()
            handle.put_chunk(chunk_index, data, mark_dirty=False)
            handle.bytes_read += len(data)
        return data
    except Exception as e:
        logger.error(f"Failed to read chunk {chunk_index} for {handle.path}: {e}")
        raise


def write_chunk(
    manager,
    fh: int,
    chunk_index: int,
    data: bytes,
    write_through: bool = False,
) -> bool:
    """Write a chunk into the handle cache, flushing evicted dirty chunks
    immediately."""
    handle = manager.get(fh)
    if not handle:
        return False

    manager._enforce_global_cache_limit()

    evicted = handle.put_chunk(chunk_index, data, mark_dirty=True)
    handle.bytes_written += len(data)

    if evicted:
        evict_idx, evict_data, evict_was_dirty = evicted
        if evict_was_dirty:
            manager._flush_single_chunk(handle, evict_idx, bytes(evict_data))

    if manager._on_chunk_write:
        manager._on_chunk_write(handle.file_id, handle.path, chunk_index, data)

    if write_through:
        manager._flush_single_chunk(handle, chunk_index, data)
        handle.mark_clean(chunk_index)

    return True


def flush_handle(manager, fh: int) -> bool:
    """Persist all dirty chunks for a single file handle to the chunk store."""
    handle = manager.get(fh)
    if not handle:
        return False
    if not handle.is_dirty:
        return True

    dirty_chunks = handle.get_dirty_chunks()
    if not dirty_chunks:
        return True

    logger.debug(f"Flushing {len(dirty_chunks)} dirty chunks for {handle.path}")
    try:
        for chunk_idx, chunk_data in dirty_chunks.items():
            manager.chunk_store.write_chunk(
                handle.file_id,
                chunk_idx,
                bytes(chunk_data),
            )
            handle.mark_clean(chunk_idx)

        manager.chunk_store.write_metadata(handle.file_id, handle.metadata)
        manager.total_flushes += 1
        return True
    except Exception as e:
        logger.error(f"Failed to flush handle {fh}: {e}")
        return False


def flush_all(manager) -> int:
    """Flush all dirty handles and return the count of successfully flushed handles."""
    with manager._lock:
        handles_to_flush = [
            fh for fh, handle in manager._handles.items() if handle.is_dirty
        ]

    flushed = 0
    for fh in handles_to_flush:
        if manager.flush_handle(fh):
            flushed += 1
    return flushed


def truncate(manager, fh: int, new_size: int) -> bool:
    """Resize the file tracked by fh to new_size, adjusting cache and chunk store."""
    handle = manager.get(fh)
    if not handle:
        return False

    old_size = handle.metadata.plaintext_size
    if new_size == old_size:
        return True

    handle._metadata_dirty = True

    if new_size == 0:
        last_chunk = -1
    else:
        last_chunk = (new_size - 1) // handle.chunk_size

    handle.invalidate_chunks_after(last_chunk)

    if new_size > 0:
        last_chunk_offset = new_size % handle.chunk_size
        if last_chunk_offset > 0:
            chunk_data = manager.read_chunk(fh, last_chunk, load_from_disk=True)
            if chunk_data:
                truncated = chunk_data[:last_chunk_offset]
                if len(truncated) < last_chunk_offset:
                    padding = b"\x00" * (last_chunk_offset - len(truncated))
                    truncated = truncated + padding
                handle.put_chunk(last_chunk, truncated, mark_dirty=True)

    handle.update_size(new_size)
    manager.chunk_store.truncate_chunks(handle.file_id, new_size)
    logger.debug(f"Truncated {handle.path} from {old_size} to {new_size}")
    return True
