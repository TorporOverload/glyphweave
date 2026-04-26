from app.common.logging import logger


def enforce_global_cache_limit(manager) -> None:
    """Evict clean chunks from open handles when the global cache ceiling is
    exceeded."""
    with manager._lock:
        current_total = sum(
            handle.cache_size_bytes for handle in manager._handles.values()
        )
        if current_total <= manager.max_total_cache_bytes:
            return

        sorted_handles = sorted(
            manager._handles.values(),
            key=lambda h: h.last_access_time,
        )
        target_free = current_total - manager.max_total_cache_bytes

        freed = 0
        for handle in sorted_handles:
            if freed >= target_free:
                break
            freed += handle.evict_chunks(target_free - freed)

    logger.debug(f"Evicted {freed} bytes from cache")

