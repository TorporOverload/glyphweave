import os
import subprocess
import time
from typing import Optional

from app.core.crypto.primitives.secure_memory import SecureMemory

from .models import MountInfo
from .probes import ProbeMixin
from .runtime import get_runtime_module


class MountMixin(ProbeMixin):
    @staticmethod
    def _ensure_windows_supported(rt) -> None:
        """Raise OSError if the current platform is not Windows."""
        if rt.platform.system() != "Windows":
            raise OSError("GlyphWeave FUSE mounts are only supported on Windows")

    def _master_key_hex(self) -> str:
        """Return the master key as a hex string, accepting SecureMemory, bytes, or
        bytearray."""
        if isinstance(self.master_key, SecureMemory):
            return self.master_key.view().hex()
        if isinstance(self.master_key, bytes):
            return self.master_key.hex()
        if isinstance(self.master_key, bytearray):
            return self.master_key.hex()
        raise TypeError("master_key must be bytes or SecureMemory")

    def _open_in_default_app(self, file_path) -> None:
        """Launch the mounted file in the OS default application using shell
        commands."""
        rt = get_runtime_module()
        self._ensure_windows_supported(rt)
        try:
            commands = [
                ["cmd", "/c", "start", "", str(file_path)],
                ["rundll32", "url.dll,FileProtocolHandler", str(file_path)],
            ]
            last_error: Exception | None = None
            for cmd in commands:
                try:
                    rt.subprocess.Popen(
                        cmd,
                        stdout=rt.subprocess.DEVNULL,
                        stderr=rt.subprocess.DEVNULL,
                    )
                    rt.logger.debug(f"Opened via launcher command: {cmd!r}")
                    return
                except Exception as e:
                    last_error = e
            if last_error is not None:
                raise last_error
        except Exception as e:
            rt.logger.warning(f"Failed to open file in default app: {e}")

    def mount_and_open(
        self,
        file_ref_id: int,
        open_in_app: bool = True,
    ) -> Optional[MountInfo]:
        """Start a FUSE mount subprocess for the given file reference and optionally
        open it."""
        rt = get_runtime_module()
        self._ensure_windows_supported(rt)
        file_ref = self.file_service.get_file_reference_with_blobs(file_ref_id)
        if not file_ref:
            return None

        with self._lock:
            if file_ref_id in self._mounts:
                return self._mounts[file_ref_id]

        mount_dir = self.mount_base / f"ref_{file_ref_id}"
        if mount_dir.exists():
            try:
                mount_dir.rmdir()
            except OSError:
                pass
        mount_dir.parent.mkdir(parents=True, exist_ok=True)

        file_entry = file_ref.file_entry
        if not file_entry:
            rt.logger.error(
                f"Unable to mount file, '{file_ref.virtual_path}' has no file_entry"
            )
            return None

        mounted_file_name = self._mount_file_name(
            file_ref.name,
            file_ref_id,
            mount_dir,
            mime_type=getattr(file_entry, "mime_type", None),
        )
        rt.logger.debug(
            f"Mount file name mapping: original='{file_ref.name}'"
            f" mounted='{mounted_file_name}'"
        )

        # blob_ids = sorted(
        #     [b.blob_id for b in file_entry.blobs],
        #     key=lambda bid: next(
        #         b.blob_index for b in file_entry.blobs if b.blob_id == bid
        #     ),
        # )

        fs = None
        fuse_thread = None
        fuse_process = None

        import ctypes
        import msvcrt
        import sys

        mount_runner = "app.core.fuse.mount_runner"
        env = os.environ.copy()

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        read_handle_value = None
        write_handle_value = None
        key_payload = bytearray()
        try:
            read_handle = ctypes.c_void_p()
            write_handle = ctypes.c_void_p()
            if not kernel32.CreatePipe(
                ctypes.byref(read_handle), ctypes.byref(write_handle), None, 0
            ):
                raise OSError(ctypes.get_last_error(), "CreatePipe failed")

            read_handle_value = read_handle.value
            write_handle_value = write_handle.value
            if read_handle_value is None or write_handle_value is None:
                raise OSError("Failed to create key pipe handles")

            os.set_handle_inheritable(read_handle_value, True)
            key_payload = bytearray(
                rt.json.dumps(
                    {
                        "master_key_hex": self._master_key_hex(),
                        "db_key_hex": self.key_service.derive_database_key(),
                    }
                ).encode("utf-8")
            )

            cmd = [
                sys.executable,
                "-m",
                mount_runner,
                "--vault-id",
                self.vault_id.decode("utf-8"),
                "--vault-path",
                str(self.vault_path),
                "--file-ref-id",
                str(file_ref_id),
                "--mount-dir",
                str(mount_dir),
                "--mount-file-name",
                mounted_file_name,
                "--vaults-data-dir",
                str(self.cache_dir.parent.parent),
                "--key-pipe-handle",
                str(read_handle_value),
            ]

            startupinfo = subprocess.STARTUPINFO()
            startupinfo.lpAttributeList = {"handle_list": [read_handle_value]}

            fuse_process = rt.subprocess.Popen(
                cmd,
                env=env,
                creationflags=rt.subprocess.CREATE_NEW_PROCESS_GROUP,
                stdout=rt.subprocess.DEVNULL,
                stderr=rt.subprocess.DEVNULL,
                startupinfo=startupinfo,
                close_fds=True,
            )

            kernel32.CloseHandle(ctypes.c_void_p(read_handle_value))
            read_handle_value = None

            try:
                write_fd = msvcrt.open_osfhandle(
                    write_handle_value,
                    os.O_WRONLY | getattr(os, "O_BINARY", 0),
                )
                write_handle_value = None
                with os.fdopen(write_fd, "wb", closefd=True) as pipe_out:
                    pipe_out.write(key_payload)
                    pipe_out.flush()
            except OSError as e:
                rt.logger.warning(f"Failed to send key payload to mount process: {e}")
        finally:
            for i in range(len(key_payload)):
                key_payload[i] = 0
            if read_handle_value is not None:
                kernel32.CloseHandle(ctypes.c_void_p(read_handle_value))
            if write_handle_value is not None:
                kernel32.CloseHandle(ctypes.c_void_p(write_handle_value))

        time.sleep(0.5)
        if fuse_process.poll() is not None:
            rt.logger.warning(
                f"FUSE mount process exited early for ref={file_ref_id}. "
                f"exit_code={fuse_process.returncode}"
            )
            try:
                if mount_dir.exists():
                    rt.shutil.rmtree(mount_dir, ignore_errors=True)
            except Exception as e:
                rt.logger.debug(f"Failed to clean mount dir after early exit: {e}")
            return None

        file_path = mount_dir / mounted_file_name
        info = MountInfo(
            file_ref_id=file_ref_id,
            file_name=mounted_file_name,
            mount_dir=mount_dir,
            file_path=file_path,
            fs=fs,
            thread=fuse_thread,
            process=fuse_process,
        )

        with self._lock:
            self._mounts[file_ref_id] = info

        if open_in_app:
            if not self._wait_for_mount_path(file_path, timeout=10.0):
                if fuse_process is not None and fuse_process.poll() is None:
                    rt.logger.warning(f"Mount path not visible for ref={file_ref_id}")
                self.unmount(file_ref_id)
                return None

            if not self._wait_for_mount_office_ready(
                mount_dir, file_path, timeout=20.0
            ):
                rt.logger.warning(
                    f"Mount not responsive for ref={file_ref_id}; falling back"
                )
                self.unmount(file_ref_id)
                return None

            rt.logger.debug(f"Mount ready for Office apps: {file_path}")
            rt.logger.debug(f"Opening mounted file: {file_path}")
            self._open_in_default_app(file_path)

        return info
