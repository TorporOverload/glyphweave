import os
import re
import threading
import time
import unicodedata
from pathlib import Path

from app.utils.file_extensions import extension_from_mime

from .runtime import get_runtime_module


class ProbeMixin:
    def _wait_for_mount_path(self, file_path: Path, timeout: float) -> bool:
        """Poll until file_path exists in the filesystem or timeout elapses."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if file_path.exists():
                    return True
            except Exception as e:
                get_runtime_module().logger.debug(f"error waiting for_mount_path: {e}")
            time.sleep(0.1)
        get_runtime_module().logger.debug(f"Mount path not visible yet: {file_path}")
        return False

    def _wait_for_mount_ready(self, file_path: Path, timeout: float) -> None:
        """Block until file_path can be opened and read or timeout elapses."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with open(file_path, "rb") as f:
                    f.read(1)
                return
            except Exception:
                time.sleep(0.1)

    def _wait_for_mount_responsive(self, file_path: Path, timeout: float) -> bool:
        """Return True when the mount responds to a probe open within timeout
        seconds."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._probe_file_open(file_path, timeout=1.0):
                return True
            time.sleep(0.2)
        return False

    def _wait_for_mount_office_ready(
        self,
        mount_dir: Path,
        file_path: Path,
        timeout: float,
    ) -> bool:
        """Poll until the mount passes listdir, open/read, and temp-file-ops probes."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not mount_dir.exists():
                time.sleep(0.1)
                continue

            if not self._probe_listdir(mount_dir, timeout=1.0):
                get_runtime_module().logger.debug(
                    f"Mount probe: listdir not ready ({mount_dir})"
                )
                time.sleep(0.2)
                continue

            if not self._probe_file_open(file_path, timeout=1.0):
                get_runtime_module().logger.debug(
                    f"Mount probe: open/read not ready ({file_path})"
                )
                time.sleep(0.2)
                continue

            if not self._probe_temp_file_ops(mount_dir, timeout=2.0):
                get_runtime_module().logger.debug(
                    f"Mount probe: temp file ops not ready ({mount_dir})"
                )
                time.sleep(0.2)
                continue

            time.sleep(0.5)
            return True

        return False

    @staticmethod
    def _probe_file_open(file_path: Path, timeout: float) -> bool:
        """Return True if file_path can be opened and read within the timeout."""
        result = {"ok": False}

        def _try_open():
            try:
                with open(file_path, "rb") as f:
                    f.read(1)
                result["ok"] = True
            except Exception:
                result["ok"] = False

        t = threading.Thread(target=_try_open, daemon=True)
        t.start()
        t.join(timeout=timeout)
        return result["ok"]

    @staticmethod
    def _probe_listdir(path: Path, timeout: float) -> bool:
        """Return True if path can be listed within the timeout."""
        result = {"ok": False}

        def _try_listdir():
            try:
                list(path.iterdir())
                result["ok"] = True
            except Exception:
                result["ok"] = False

        t = threading.Thread(target=_try_listdir, daemon=True)
        t.start()
        t.join(timeout=timeout)
        return result["ok"]

    @staticmethod
    def _probe_temp_file_ops(path: Path, timeout: float) -> bool:
        """Return True if create, rename, and delete operations succeed in path within
        timeout."""
        result = {"ok": False}
        token = f"~$gw_{int(time.time() * 1000)}"
        temp_a = path / f"{token}.tmp"
        temp_b = path / f"{token}.bak"

        def _try_ops():
            try:
                with open(temp_a, "wb") as f:
                    f.write(b"x")
                os.replace(temp_a, temp_b)
                os.remove(temp_b)
                result["ok"] = True
            except Exception:
                result["ok"] = False

        t = threading.Thread(target=_try_ops, daemon=True)
        t.start()
        t.join(timeout=timeout)
        return result["ok"]

    @staticmethod
    def _mount_file_name(
        original_name: str,
        file_ref_id: int,
        mount_dir: Path,
        mime_type: str | None = None,
    ) -> str:
        """Derive a safe, length-bounded mount filename from the original name and MIME
        type."""
        raw_suffix = Path(original_name).suffix.lower()
        if re.fullmatch(r"\.[a-z0-9]{1,10}", raw_suffix):
            suffix = raw_suffix
        else:
            suffix = extension_from_mime(mime_type) or ".bin"

        stem = Path(original_name).stem or f"file_{file_ref_id}"
        normalized = unicodedata.normalize("NFKD", stem)
        ascii_stem = normalized.encode("ascii", "ignore").decode("ascii")
        safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", ascii_stem).strip(" ._")
        if not safe_stem:
            safe_stem = f"file_{file_ref_id}"

        max_full_path = 220
        room = max_full_path - len(str(mount_dir)) - 1
        max_name_len = min(64, max(24, room))

        candidate = f"{safe_stem}{suffix}"
        if len(candidate) <= max_name_len:
            return candidate

        reserve = len(suffix) + len(str(file_ref_id)) + 1
        if max_name_len <= reserve:
            return f"v{file_ref_id}{suffix}"

        truncated = safe_stem[: max_name_len - reserve].rstrip(" .")
        if not truncated:
            truncated = "v"
        return f"{truncated}_{file_ref_id}{suffix}"
