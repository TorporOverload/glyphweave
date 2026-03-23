import errno
import stat
import time

from mfusepy import FuseOSError


def create_op(fs, path, mode, fi=None):
    """Create a new temp file in the filesystem and return its file handle integer."""
    del fi
    if fs._is_main_path(path):
        raise FuseOSError(errno.EEXIST)

    name = path.lstrip("/")
    fs._temp_files[name] = bytearray()
    now = time.time()
    fs._temp_meta[name] = {
        "size": 0,
        "mode": stat.S_IFREG | (mode & 0o777),
        "ctime": now,
        "mtime": now,
        "atime": now,
    }
    fh = fs._temp_fh_counter
    fs._temp_fh_counter += 1
    fs._temp_file_handles[fh] = name
    return fh


def unlink_op(fs, path):
    """Delete a temp file, or raise EACCES for the main file and ENOENT for unknown
    paths."""
    name = path.lstrip("/")
    if name in fs._temp_files:
        fs._temp_files.pop(name, None)
        fs._temp_meta.pop(name, None)
        return 0
    if fs._is_main_path(path):
        raise FuseOSError(errno.EACCES)
    raise FuseOSError(errno.ENOENT)


def mkdir_op(fs, path, mode):
    """Reject all mkdir calls with EACCES as this filesystem does not support
    directories."""
    del fs, path, mode
    raise FuseOSError(errno.EACCES)


def chmod_op(fs, path, mode):
    """Apply a permission change to the main file's mode bits."""
    if fs._is_main_path(path):
        fs.metadata.mode = stat.S_IFREG | (mode & 0o777)
    return 0


def chown_op(fs, path, uid, gid):
    """Accept a chown call and return 0 without changing ownership."""
    del fs, path, uid, gid
    return 0


def utimens_op(fs, path, times=None):
    """Update access and modification timestamps for the main or a temp file."""
    if not fs._is_main_path(path):
        name = path.lstrip("/")
        if name in fs._temp_meta:
            now = time.time()
            if times is None:
                fs._temp_meta[name]["atime"] = now
                fs._temp_meta[name]["mtime"] = now
            else:
                atime_spec, mtime_spec = times
                fs._temp_meta[name]["atime"] = (
                    float(atime_spec[0])
                    if isinstance(atime_spec, (list, tuple))
                    else float(atime_spec)
                )
                fs._temp_meta[name]["mtime"] = (
                    float(mtime_spec[0])
                    if isinstance(mtime_spec, (list, tuple))
                    else float(mtime_spec)
                )
        return 0

    if times is None:
        fs.metadata.accessed_at = time.time()
        fs.metadata.modified_at = time.time()
    else:
        atime_spec, mtime_spec = times
        fs.metadata.accessed_at = (
            float(atime_spec[0])
            if isinstance(atime_spec, (list, tuple))
            else float(atime_spec)
        )
        fs.metadata.modified_at = (
            float(mtime_spec[0])
            if isinstance(mtime_spec, (list, tuple))
            else float(mtime_spec)
        )
    return 0


def access_op(fs, path, amode):
    """Return 0 for root, the main file, and known temp files; raise ENOENT
    otherwise."""
    del amode
    if path == "/" or fs._is_main_path(path):
        return 0
    name = path.lstrip("/")
    if name in fs._temp_files:
        return 0
    raise FuseOSError(errno.ENOENT)


def rename_op(fs, old, new):
    """Handle rename between temp and main files, committing or staging content as
    needed."""
    old_name = old.lstrip("/")
    new_name = new.lstrip("/")
    old_is_main = fs._is_main_path(old)
    new_is_main = fs._is_main_path(new)

    if not old_is_main and new_is_main:
        data = bytes(fs._temp_files.get(old_name, b""))
        fs._write_full_file(data)
        fs._temp_files.pop(old_name, None)
        fs._temp_meta.pop(old_name, None)
        return 0

    if old_is_main and not new_is_main:
        data = fs._read_full_file()
        fs._temp_files[new_name] = bytearray(data)
        now = time.time()
        fs._temp_meta[new_name] = {
            "size": len(data),
            "mode": stat.S_IFREG | 0o666,
            "ctime": now,
            "mtime": now,
            "atime": now,
        }
        return 0

    if not old_is_main and not new_is_main:
        if old_name not in fs._temp_files:
            raise FuseOSError(errno.ENOENT)
        fs._temp_files[new_name] = fs._temp_files.pop(old_name)
        if old_name in fs._temp_meta:
            fs._temp_meta[new_name] = fs._temp_meta.pop(old_name)
        return 0

    return 0
