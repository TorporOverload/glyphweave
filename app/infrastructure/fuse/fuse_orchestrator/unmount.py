import threading
import time
from pathlib import Path
from typing import Dict, Optional

from .models import MountInfo
from .runtime import get_runtime_module


def is_mounted(
    mounts: Dict[int, MountInfo], lock: threading.Lock, file_ref_id: int
) -> bool:
    """Return True if a FUSE mount is currently active for the given file reference."""
    with lock:
        return file_ref_id in mounts


def get_mounted_path(
    mounts: Dict[int, MountInfo], lock: threading.Lock, file_ref_id: int
) -> Optional[Path]:
    """Return the mounted file path for a reference, or None if not mounted."""
    with lock:
        info = mounts.get(file_ref_id)
        return info.file_path if info else None


def active_mount_count(mounts: Dict[int, MountInfo], lock: threading.Lock) -> int:
    """Return the number of currently active FUSE mounts."""
    with lock:
        return len(mounts)


def get_active_mounts(
    mounts: Dict[int, MountInfo], lock: threading.Lock
) -> Dict[int, MountInfo]:
    """Return a snapshot dict of all active MountInfo objects keyed by file_ref_id."""
    with lock:
        return dict(mounts)


def do_unmount(
    mounts: Dict[int, MountInfo],
    lock: threading.Lock,
    file_ref_id: int,
    background: bool = False,
) -> bool:
    """Tear down the FUSE mount for file_ref_id, optionally in a background thread."""
    rt = get_runtime_module()
    with lock:
        info = mounts.get(file_ref_id)
        if info is None:
            return False

    if background:
        def _run_background() -> None:
            success = unmount_info(file_ref_id, info)
            if success:
                with lock:
                    mounts.pop(file_ref_id, None)
            else:
                rt.logger.warning(
                    "Unmount failed for %s, mount entry retained", file_ref_id
                )

        thread = rt.threading.Thread(
            target=_run_background,
            name=f"glyphweave_unmount_{file_ref_id}",
            daemon=True,
        )
        thread.start()
        return True

    success = unmount_info(file_ref_id, info)
    if success:
        with lock:
            mounts.pop(file_ref_id, None)
    else:
        rt.logger.warning("Unmount failed for %s, mount entry retained", file_ref_id)
    return success


def unmount_info(file_ref_id: int, info: MountInfo) -> bool:
    """Send CTRL_BREAK, run net-use delete, wait for the FUSE process,
    and clean up the mount dir."""
    rt = get_runtime_module()
    if rt.platform.system() != "Windows":
        raise OSError("GlyphWeave FUSE mounts are only supported on Windows")

    def _run_unmount() -> None:
        rt.subprocess.run(
            ["net", "use", str(info.mount_dir), "/delete", "/y"],
            check=False,
            capture_output=True,
            timeout=10,
            creationflags=rt.subprocess.CREATE_NO_WINDOW,
        )

    if info.process is None:
        wait_for_handles_to_close(info, timeout=20.0)

    signal_failed = False
    unmount_cmd_failed = False
    try:
        if info.process is not None:
            try:
                info.process.send_signal(
                    getattr(__import__("signal"), "CTRL_BREAK_EVENT")
                )
            except Exception as e:
                signal_failed = True
                rt.logger.warning(f"CTRL_BREAK_EVENT failed (non-fatal): {e}")
        _run_unmount()
    except Exception as e:
        unmount_cmd_failed = True
        rt.logger.warning(f"Unmount command failed for {info.mount_dir}: {e}")

    time.sleep(0.2)
    if info.process is not None:
        try:
            info.process.wait(timeout=10.0)
        except Exception as e:
            rt.logger.warning(f"Error killing FUSE process: {e}")

        if info.process.poll() is None:
            try:
                info.process.terminate()
            except Exception as e:
                rt.logger.warning(f"Error killing FUSE process: {e}")

    if info.thread is not None:
        info.thread.join(timeout=10.0)

    if info.thread is not None and info.thread.is_alive():
        rt.logger.debug(
            f"FUSE thread still alive for ref={file_ref_id}; retrying unmount"
        )
        try:
            _run_unmount()
        except Exception as e:
            rt.logger.warning(f"Retry unmount failed for {info.mount_dir}: {e}")

        if info.thread is not None:
            info.thread.join(timeout=10.0)
            if info.thread.is_alive():
                rt.logger.debug(
                    f"FUSE thread for ref={file_ref_id} still alive after unmount"
                )

    process_still_running = (
        info.process is not None and info.process.poll() is None
    )
    if process_still_running and signal_failed and unmount_cmd_failed:
        rt.logger.error(
            f"FUSE process for ref={file_ref_id} could not be stopped; "
            f"skipping mount dir cleanup to avoid data loss"
        )
        return False

    try:
        if info.mount_dir.exists():
            rt.shutil.rmtree(info.mount_dir, ignore_errors=True)
    except Exception as e:
        rt.logger.warning(f"Failed to clean up mount dir {info.mount_dir}: {e}")
        return False

    return True


def wait_for_handles_to_close(info: MountInfo, timeout: float) -> None:
    """Block until the filesystem's handle manager reports zero open handles 
    or timeout."""
    fs = info.fs
    handle_manager = getattr(fs, "handle_manager", None)
    if handle_manager is None:
        return

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if handle_manager.open_handle_count == 0:
                return
        except AttributeError:
            return
        time.sleep(0.25)


def cleanup_all(
    mounts: Dict[int, MountInfo],
    lock: threading.Lock,
    mount_base: Path,
) -> int:
    """Unmount all active mounts, remove the mount base directory,
    and return the count removed."""
    with lock:
        ref_ids = list(mounts.keys())

    for ref_id in ref_ids:
        do_unmount(mounts, lock, ref_id)

    count = len(ref_ids)
    if mount_base.exists():
        get_runtime_module().shutil.rmtree(mount_base, ignore_errors=True)
    mount_base.mkdir(parents=True, exist_ok=True)
    return count


def cleanup_stale_mounts(mount_base: Path) -> int:
    """Best-effort cleanup for mount directories left behind by a crashed app."""
    if not mount_base.exists():
        return 0

    cleaned = 0
    rt = get_runtime_module()
    for entry in list(mount_base.iterdir()):
        if entry.is_dir():
            info = MountInfo(
                file_ref_id=-1,
                file_name=entry.name,
                mount_dir=entry,
                file_path=entry,
                fs=None,
            )
            if unmount_info(-1, info):
                cleaned += 1
            continue

        try:
            entry.unlink()
            cleaned += 1
        except Exception as exc:
            rt.logger.warning(
                "Failed to remove stale mount artifact %s: %s", entry, exc)

    mount_base.mkdir(parents=True, exist_ok=True)
    return cleaned
