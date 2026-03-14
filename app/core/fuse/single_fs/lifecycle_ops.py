def flush_file(fs, path, fh):
    """Handle a FUSE flush call; always returns 0 as flush is handled at release."""
    del fs, path, fh
    return 0


def fsync_file(fs, path, datasync, fh):
    """Handle a FUSE fsync call by delegating to flush_file."""
    del datasync
    return flush_file(fs, path, fh)


def statfs(fs, path):
    """Return filesystem statistics with generous free space for the FUSE mount."""
    del path
    return {
        "f_bsize": fs.chunk_size,
        "f_frsize": fs.chunk_size,
        "f_blocks": 1024 * 1024,
        "f_bfree": 1024 * 1024,
        "f_bavail": 1024 * 1024,
        "f_files": 2,
        "f_ffree": 1_000_000,
        "f_favail": 1_000_000,
        "f_namemax": 255,
    }


def destroy_fs(fs, path):
    """Flush and close all handles and clear temp file state when the filesystem is
    unmounted."""
    del path
    fs.handle_manager.close_all(flush=True)
    fs._temp_files.clear()
    fs._temp_meta.clear()
    fs._temp_file_handles.clear()
