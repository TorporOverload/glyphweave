from app.utils.logging import logger


def enforce_global_cache_limit(manager) -> None:
    """Evict clean chunks from open handles when the global cache ceiling is
    exceeded."""
    current_total = manager.total_cache_bytes
    if current_total <= manager.max_total_cache_bytes:
        return

    target_free = current_total - int(manager.max_total_cache_bytes * 0.8)
    freed = 0

    with manager._lock:
        sorted_handles = sorted(
            manager._handles.values(),
            key=lambda h: h.cache_size_bytes,
            reverse=True,
        )

    for handle in sorted_handles:
        if freed >= target_free:
            break

        if handle.is_dirty:
            manager.flush_handle(handle.fh)

        with handle._lock:
            to_evict = [
                idx
                for idx in list(handle._chunks_cache.keys())
                if idx not in handle._dirty_chunks
            ]

            for idx in to_evict:
                chunk = handle._chunks_cache.pop(idx)
                freed += len(chunk) if chunk else 0
                handle._secure_clear_chunk(chunk)
                if freed >= target_free:
                    break

    logger.debug(f"Evicted {freed} bytes from cache")
