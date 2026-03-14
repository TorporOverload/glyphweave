import errno
import os
import stat
import time

from mfusepy import FuseOSError

from app.utils.logging import logger


def getattr_op(fs, path, fh=None):
    """Return POSIX stat attributes for root, the main file, or a temp file."""
    now = int(time.time())
    uid = os.getuid() if hasattr(os, "getuid") else 0
    gid = os.getgid() if hasattr(os, "getgid") else 0
    base = {
        "st_uid": uid,
        "st_gid": gid,
        "st_atime": now,
        "st_ctime": now,
        "st_mtime": now,
    }

    if path == "/":
        return {
            **base,
            "st_mode": stat.S_IFDIR | 0o755,
            "st_nlink": 2,
            "st_size": 4096,
        }

    if fs._is_main_path(path):
        size = fs.metadata.plaintext_size
        if fh is not None:
            handle = fs.handle_manager.get(fh)
            if handle:
                size = handle.metadata.plaintext_size
        return {
            **base,
            "st_mode": fs.metadata.mode,
            "st_nlink": 1,
            "st_size": size,
            "st_ctime": int(fs.metadata.created_at),
            "st_mtime": int(fs.metadata.modified_at),
            "st_atime": int(fs.metadata.accessed_at),
        }

    name = path.lstrip("/")
    if name in fs._temp_files:
        meta = fs._temp_meta.get(name, {})
        return {
            **base,
            "st_mode": meta.get("mode", stat.S_IFREG | 0o666),
            "st_nlink": 1,
            "st_size": meta.get("size", len(fs._temp_files[name])),
            "st_ctime": int(meta.get("ctime", now)),
            "st_mtime": int(meta.get("mtime", now)),
            "st_atime": int(meta.get("atime", now)),
        }

    raise FuseOSError(errno.ENOENT)


def readdir_op(fs, path, fh):
    """Return directory entries for the root directory including the main and temp
    files."""
    del fh
    if path != "/":
        raise FuseOSError(errno.ENOTDIR)
    entries = [".", "..", fs.file_name]
    entries.extend(fs._temp_files.keys())
    return entries


def open_op(fs, path, flags):
    """Open a file and return a file handle integer, routing to temp or main file
    handling."""
    if not fs._is_main_path(path):
        name = path.lstrip("/")
        if name in fs._temp_files:
            fh = fs._temp_fh_counter
            fs._temp_fh_counter += 1
            fs._temp_file_handles[fh] = name
            return fh
        raise FuseOSError(errno.ENOENT)
    return fs._open_main(flags)


def read_op(fs, path, size, offset, fh):
    """Read size bytes at offset from a temp or main file handle."""
    del path
    temp_name = fs._temp_file_handles.get(fh)
    if temp_name is not None:
        data = fs._temp_files.get(temp_name, bytearray())
        return bytes(data[offset : offset + size])

    handle = fs.handle_manager.get(fh)
    if handle is None:
        raise FuseOSError(errno.EBADF)

    file_size = handle.metadata.plaintext_size
    if offset >= file_size:
        return b""

    end_offset = min(offset + size, file_size)
    read_size = end_offset - offset
    start_chunk = offset // fs.chunk_size
    end_chunk = (end_offset - 1) // fs.chunk_size if end_offset > 0 else 0

    result = bytearray()
    for chunk_idx in range(start_chunk, end_chunk + 1):
        chunk_data = fs.handle_manager.read_chunk(fh, chunk_idx)
        if chunk_data is None:
            chunk_data = b""
        result.extend(chunk_data)

    start_in_first_chunk = offset % fs.chunk_size
    return bytes(result[start_in_first_chunk : start_in_first_chunk + read_size])


def write_op(fs, path, data, offset, fh):
    """Write data at offset into a temp or main file handle and return bytes
    written."""
    del path
    temp_name = fs._temp_file_handles.get(fh)
    if temp_name is not None:
        buf = fs._temp_files.get(temp_name)
        if buf is None:
            raise FuseOSError(errno.EBADF)

        end_offset = offset + len(data)
        if end_offset > len(buf):
            buf.extend(b"\x00" * (end_offset - len(buf)))
        buf[offset:end_offset] = data

        meta = fs._temp_meta.setdefault(
            temp_name,
            {
                "size": len(buf),
                "mode": stat.S_IFREG | 0o666,
                "ctime": time.time(),
                "mtime": time.time(),
                "atime": time.time(),
            },
        )
        meta["size"] = len(buf)
        meta["mtime"] = time.time()
        return len(data)

    handle = fs.handle_manager.get(fh)
    if handle is None:
        raise FuseOSError(errno.EBADF)

    data_len = len(data)
    if data_len == 0:
        return 0

    end_offset = offset + data_len
    start_chunk = offset // fs.chunk_size
    end_chunk = (end_offset - 1) // fs.chunk_size

    data_pos = 0
    for chunk_idx in range(start_chunk, end_chunk + 1):
        chunk_start = chunk_idx * fs.chunk_size
        chunk_end = chunk_start + fs.chunk_size
        write_start = max(offset, chunk_start) - chunk_start
        write_end = min(end_offset, chunk_end) - chunk_start
        write_len = write_end - write_start

        if write_start > 0 or write_end < fs.chunk_size:
            existing = fs.handle_manager.read_chunk(fh, chunk_idx)
            if existing is None:
                existing = b"\x00" * fs.chunk_size
            chunk_data = bytearray(existing)
            if len(chunk_data) < write_end:
                chunk_data.extend(b"\x00" * (write_end - len(chunk_data)))
            chunk_data[write_start:write_end] = data[data_pos : data_pos + write_len]
            chunk_data = bytes(chunk_data)
        else:
            chunk_data = data[data_pos : data_pos + write_len]

        fs.handle_manager.write_chunk(fh, chunk_idx, chunk_data)
        data_pos += write_len

    new_size = max(handle.metadata.plaintext_size, end_offset)
    handle.update_size(new_size)
    fs.metadata.plaintext_size = new_size
    return data_len


def truncate_op(fs, path, length, fh=None):
    """Truncate a temp or main file to length bytes via the given file handle."""
    del path
    if fh is None:
        raise FuseOSError(errno.EINVAL)

    temp_name = fs._temp_file_handles.get(fh)
    if temp_name is not None:
        buf = fs._temp_files.get(temp_name)
        if buf is None:
            raise FuseOSError(errno.EBADF)

        if length < len(buf):
            del buf[length:]
        elif length > len(buf):
            buf.extend(b"\x00" * (length - len(buf)))

        meta = fs._temp_meta.setdefault(
            temp_name,
            {
                "size": len(buf),
                "mode": stat.S_IFREG | 0o666,
                "ctime": time.time(),
                "mtime": time.time(),
                "atime": time.time(),
            },
        )
        meta["size"] = len(buf)
        meta["mtime"] = time.time()
        return 0

    handle = fs.handle_manager.get(fh)
    if handle:
        fs.handle_manager.truncate(fh, length)
        fs.metadata.plaintext_size = length
    return 0


def release_op(fs, path, fh):
    """Flush dirty chunks to blobs, clean up WAL entries, and release the file
    handle."""
    temp_name = fs._temp_file_handles.pop(fh, None)
    if temp_name is not None:
        return 0

    handle = fs.handle_manager.get(fh)
    if handle is None:
        return 0

    has_dirty = handle.is_dirty
    dirty_chunks = handle.get_dirty_chunks() if has_dirty else {}
    flush_failed = False

    if has_dirty:
        try:
            fs.chunk_store.flush_to_blobs(
                file_id=fs.file_id,
                file_ref_id=fs.file_ref_id,
                dirty_chunks=dirty_chunks,
                original_size=handle.metadata.plaintext_size,
            )
            fs._refresh_after_flush()
        except Exception as e:
            flush_failed = True
            logger.error(f"Failed to flush blobs for {path}: {e}", exc_info=True)

    if not flush_failed:
        try:
            entries = fs.wal_service.get_pending_entries(fs.file_ref_id)
            if entries:
                fs.wal_service.mark_flushed([e.id for e in entries])
            fs.wal_service.checkpoint(fs.file_ref_id)
        except Exception as e:
            logger.error(f"Failed WAL cleanup for {path}: {e}", exc_info=True)

    fs.handle_manager.release(fh, flush=False)
    fs._open_count = max(0, fs._open_count - 1)
    if flush_failed:
        raise FuseOSError(errno.EIO)
    return 0
