import time
from typing import Dict, Optional

from .models import MountInfo
from .runtime import get_runtime_module


class UnmountMixin:
    def is_mounted(self, file_ref_id: int) -> bool:
        """Return True if a FUSE mount is currently active for the given file
        reference."""
        with self._lock:
            return file_ref_id in self._mounts

    def get_mounted_path(self, file_ref_id: int) -> Optional[object]:
        """Return the mounted file path for a reference, or None if not mounted."""
        with self._lock:
            info = self._mounts.get(file_ref_id)
            return info.file_path if info else None

    @property
    def active_mount_count(self) -> int:
        """Return the number of currently active FUSE mounts."""
        with self._lock:
            return len(self._mounts)

    def get_active_mounts(self) -> Dict[int, MountInfo]:
        """Return a snapshot dict of all active MountInfo objects keyed by
        file_ref_id."""
        with self._lock:
            return dict(self._mounts)

    def unmount(self, file_ref_id: int, background: bool = False) -> bool:
        """Tear down the FUSE mount for file_ref_id, optionally in a background
        thread."""
        rt = get_runtime_module()
        with self._lock:
            if file_ref_id not in self._mounts:
                return False
            info = self._mounts.pop(file_ref_id)

        if background:
            thread = rt.threading.Thread(
                target=self._unmount_info,
                args=(file_ref_id, info),
                name=f"glyphweave_unmount_{file_ref_id}",
                daemon=True,
            )
            thread.start()
            return True

        self._unmount_info(file_ref_id, info)
        return True

    def _unmount_info(self, file_ref_id: int, info: MountInfo) -> None:
        """Send CTRL_BREAK, run net-use delete, wait for the FUSE process, and clean up
        the mount dir."""
        rt = get_runtime_module()
        if rt.platform.system() != "Windows":
            raise OSError("GlyphWeave FUSE mounts are only supported on Windows")

        def _run_unmount() -> None:
            rt.subprocess.run(
                ["net", "use", str(info.mount_dir), "/delete", "/y"],
                check=False,
                capture_output=True,
                timeout=10,
            )

        if info.process is None:
            self._wait_for_handles_to_close(info, timeout=20.0)

        try:
            if info.process is not None:
                try:
                    info.process.send_signal(
                        getattr(__import__("signal"), "CTRL_BREAK_EVENT")
                    )
                except Exception as e:
                    rt.logger.warning(f"CTRL_BREAK_EVENT failed (non-fatal): {e}")
            _run_unmount()
        except Exception as e:
            rt.logger.warning(f"Unmount command failed for {info.mount_dir}: {e}")

        time.sleep(0.2)
        if info.process is not None:
            try:
                info.process.wait(timeout=10.0)
            except Exception as e:
                rt.logger.warning(f"Error kiling fuse: {e}")

            if info.process.poll() is None:
                try:
                    info.process.terminate()
                except Exception as e:
                    rt.logger.warning(f"Error kiling fuse: {e}")

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

        try:
            if info.mount_dir.exists():
                rt.shutil.rmtree(info.mount_dir, ignore_errors=True)
        except Exception as e:
            rt.logger.warning(f"Failed to clean up mount dir {info.mount_dir}: {e}")

    def _wait_for_handles_to_close(self, info: MountInfo, timeout: float) -> None:
        """Block until the filesystem's handle manager reports zero open handles or
        timeout."""
        fs = info.fs
        handle_manager = getattr(fs, "handle_manager", None)
        if handle_manager is None:
            return

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if handle_manager.open_handle_count == 0:
                    return
            except Exception:
                return
            time.sleep(0.25)

    def cleanup_all(self) -> int:
        """Unmount all active mounts, remove the mount base directory, and return the
        count removed."""
        with self._lock:
            ref_ids = list(self._mounts.keys())

        for ref_id in ref_ids:
            self.unmount(ref_id)

        count = len(ref_ids)
        if self.mount_base.exists():
            get_runtime_module().shutil.rmtree(self.mount_base, ignore_errors=True)
        self.mount_base.mkdir(parents=True, exist_ok=True)
        return count
