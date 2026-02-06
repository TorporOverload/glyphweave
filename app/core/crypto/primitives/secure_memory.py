import ctypes

from app.utils.logging import logger

# Load Kernel32 for Windows memory locking
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class SecureMemory:
    """Windows-specific secure memory management for sensitive keys."""

    # https://homes.di.unimi.it/sisop/Laboratorio/Msdn/VirtualAlloc_files/rightframe.htm
    # https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    # https://systemweakness.com/how-to-use-the-win32api-with-python3-3adde999211b

    def __init__(self, data: bytes):
        self._data = bytearray(data)
        self._size = len(self._data)
        self.is_cleared = False

        # Access the underlying memory buffer
        c_array_type = ctypes.c_char * self._size
        self._buffer = c_array_type.from_buffer(self._data)
        self._address = ctypes.addressof(self._buffer)

        # Lock the memory in RAM to prevent swapping to disk
        if not kernel32.VirtualLock(
            ctypes.c_void_p(self._address), ctypes.c_size_t(self._size)
        ):
            error_code = ctypes.get_last_error()
            logger.warning(
                f"VirtualLock failed: {error_code}. Key might be swapped to disk."
            )

    def get(self) -> bytes:
        """Returns a temporary copy of the sensitive data."""
        if self.is_cleared:
            raise ValueError("Cannot access cleared secure bytes")
        return bytes(self._data)

    def clear(self) -> None:
        """Securely zero out the memory and release the OS lock."""
        if not self.is_cleared:
            self.secure_zero(self._data)
            kernel32.VirtualUnlock(
                ctypes.c_void_p(self._address), ctypes.c_size_t(self._size)
            )
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
