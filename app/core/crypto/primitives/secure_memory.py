import ctypes
import platform

from app.utils.logging import logger

# Platform-specific memory locking
_PLATFORM = platform.system()
_kernel32 = None
_libc = None

if _PLATFORM == "Windows":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
elif _PLATFORM in ("Linux", "Darwin"):
    try:
        _libc = ctypes.CDLL("libc.so.6" if _PLATFORM == "Linux" else "libc.dylib")
    except OSError:
        _libc = None


class SecureMemory:
    """Cross-platform secure memory management for sensitive keys.

    On Windows: Uses VirtualLock/VirtualUnlock
    On Linux/macOS: Uses mlock/munlock
    """

    # https://homes.di.unimi.it/sisop/Laboratorio/Msdn/VirtualAlloc_files/rightframe.htm
    # https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    # https://systemweakness.com/how-to-use-the-win32api-with-python3-3adde999211b

    def __init__(self, data: bytes):
        self._data = bytearray(data)
        self._size = len(self._data)
        self.is_cleared = False
        self._locked = False

        # Access the underlying memory buffer
        c_array_type = ctypes.c_char * self._size
        self._buffer = c_array_type.from_buffer(self._data)
        self._address = ctypes.addressof(self._buffer)

        # Lock the memory in RAM to prevent swapping to disk
        self._lock_memory()

    def _lock_memory(self) -> None:
        """Lock memory using platform-specific API."""
        if _PLATFORM == "Windows" and _kernel32:
            if not _kernel32.VirtualLock(
                ctypes.c_void_p(self._address), ctypes.c_size_t(self._size)
            ):
                error_code = ctypes.get_last_error()
                logger.warning(
                    f"VirtualLock failed: {error_code}. Key might be swapped to disk."
                )
            else:
                self._locked = True
        elif _libc:
            result = _libc.mlock(ctypes.c_void_p(self._address), self._size)
            if result != 0:
                logger.warning("mlock failed. Key might be swapped to disk.")
            else:
                self._locked = True
        else:
            logger.debug("No memory locking available on this platform.")

    def _unlock_memory(self) -> None:
        """Unlock memory using platform-specific API."""
        if not self._locked:
            return

        if _PLATFORM == "Windows" and _kernel32:
            _kernel32.VirtualUnlock(
                ctypes.c_void_p(self._address), ctypes.c_size_t(self._size)
            )
        elif _libc:
            _libc.munlock(ctypes.c_void_p(self._address), self._size)

    def get(self) -> bytes:
        """Returns a temporary copy of the sensitive data."""
        if self.is_cleared:
            raise ValueError("Cannot access cleared secure bytes")
        return bytes(self._data)

    def clear(self) -> None:
        """Securely zero out the memory and release the OS lock."""
        if not self.is_cleared:
            self.secure_zero(self._data)
            self._unlock_memory()
            self.is_cleared = True
            logger.debug("SecureBytes cleared and unlocked")

    @staticmethod
    def secure_zero(data: bytearray) -> None:
        """Overwrites bytearray with zeros to clear sensitive data."""
        logger.debug("Attempring to zero out master key")
        for i in range(len(data)):
            data[i] = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()
        return False

    def __del__(self):
        if getattr(self, "is_cleared", True) is False:
            self.clear()
