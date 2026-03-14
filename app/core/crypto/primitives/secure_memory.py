import ctypes
import platform

from app.core.crypto.types import KeyMaterial
from app.exceptions.crypto import SecureMemoryError
from app.utils.logging import logger

# Platform-specific memory locking
_PLATFORM = platform.system()
_kernel32 = None
_WIN_MEM_COMMIT = 0x1000  # reserve and commit pages
_WIN_MEM_RESERVE = 0x2000  # reserve address pafe only
_WIN_MEM_RELEASE = 0x8000  # free the allocation
_WIN_PAGE_READWRITE = 0x04  # read and write only no excecution allowed


class _SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", ctypes.c_ushort),
        ("wReserved", ctypes.c_ushort),
        ("dwPageSize", ctypes.c_uint),
        ("lpMinimumApplicationAddress", ctypes.c_void_p),
        ("lpMaximumApplicationAddress", ctypes.c_void_p),
        ("dwActiveProcessorMask", ctypes.c_size_t),
        ("dwNumberOfProcessors", ctypes.c_uint),
        ("dwProcessorType", ctypes.c_uint),
        ("dwAllocationGranularity", ctypes.c_uint),
        ("wProcessorLevel", ctypes.c_ushort),
        ("wProcessorRevision", ctypes.c_ushort),
    ]


if _PLATFORM == "Windows":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.GetSystemInfo.argtypes = [ctypes.POINTER(_SYSTEM_INFO)]
    _kernel32.GetSystemInfo.restype = None
    _kernel32.VirtualAlloc.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint,
        ctypes.c_uint,
    ]
    _kernel32.VirtualAlloc.restype = ctypes.c_void_p
    _kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint]
    _kernel32.VirtualFree.restype = ctypes.c_int
    _kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _kernel32.VirtualLock.restype = ctypes.c_int
    _kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _kernel32.VirtualUnlock.restype = ctypes.c_int


def _key_material_size(data: KeyMaterial) -> int:
    """Return the byte size of a KeyMaterial value."""
    if isinstance(data, memoryview):
        return data.nbytes
    return len(data)


def _round_up_to_page(size: int, page_size: int) -> int:
    """Round size up to the nearest multiple of page_size."""
    if size <= 0:
        return 0
    return ((size + page_size - 1) // page_size) * page_size


class SecureMemory:
    """Windows-only secure memory management for sensitive keys."""

    def __init__(self, data: KeyMaterial):
        if _PLATFORM != "Windows" or not _kernel32:
            raise SecureMemoryError("SecureMemory is only supported on Windows")

        self._size = _key_material_size(data)
        self._alloc_size = 0
        self._page_size = 0
        self._address = 0
        self._buffer = None
        self._data = None
        self._view = None
        self.is_cleared = False
        self._locked = False

        try:
            if self._size == 0:
                self._data = bytearray()
                self._view = memoryview(self._data).toreadonly()
            else:
                self._initialize_windows_storage(data)
        except Exception:
            self.clear()
            self.is_cleared = True
            raise

    @classmethod
    def consume_mutable(cls, data: bytearray) -> "SecureMemory":
        """Build secure storage from a mutable buffer and zero the source."""
        try:
            return cls(data)
        finally:
            cls.secure_zero(data)

    def _initialize_windows_storage(self, data: KeyMaterial) -> None:
        """Allocate, lock, and populate a page-aligned Windows virtual memory region."""
        self._page_size = self._get_windows_page_size()
        self._alloc_size = _round_up_to_page(self._size, self._page_size)
        self._address = self._virtual_alloc(self._alloc_size)
        self._lock_memory()
        self._copy_to_address(data)
        buffer_type = ctypes.c_ubyte * self._size
        self._buffer = buffer_type.from_address(self._address)
        self._view = self._make_readonly_view(self._buffer)

    def _get_windows_page_size(self) -> int:
        """Retrieve the system memory page size via GetSystemInfo."""
        if not _kernel32:
            raise SecureMemoryError("Windows secure memory APIs are unavailable")

        system_info = _SYSTEM_INFO()
        _kernel32.GetSystemInfo(ctypes.byref(system_info))
        if system_info.dwPageSize <= 0:
            raise SecureMemoryError("GetSystemInfo returned an invalid page size")
        return int(system_info.dwPageSize)

    def _virtual_alloc(self, size: int) -> int:
        """Allocate a committed, read-write virtual memory region of the given size."""
        if not _kernel32:
            raise SecureMemoryError("Windows secure memory APIs are unavailable")

        address = _kernel32.VirtualAlloc(
            None,
            ctypes.c_size_t(size),
            _WIN_MEM_COMMIT | _WIN_MEM_RESERVE,
            _WIN_PAGE_READWRITE,
        )
        if not address:
            error_code = ctypes.get_last_error()
            raise SecureMemoryError(f"VirtualAlloc failed: {error_code}")
        return int(address)

    def _copy_to_address(self, data: KeyMaterial) -> None:
        """Copy key material bytes into the allocated virtual memory address."""
        if self._size == 0 or not self._address:
            return

        source: bytes | int
        source_buffer: ctypes.Array[ctypes.c_ubyte] | None = None
        if isinstance(data, memoryview):
            try:
                source_view = data.cast("B")
            except TypeError:
                source = data.tobytes()
            else:
                if source_view.readonly:
                    source = source_view.tobytes()
                else:
                    source_buffer = (ctypes.c_ubyte * self._size).from_buffer(
                        source_view
                    )
                    source = ctypes.addressof(source_buffer)
        elif isinstance(data, bytearray):
            source_buffer = (ctypes.c_ubyte * self._size).from_buffer(data)
            source = ctypes.addressof(source_buffer)
        else:
            source = data

        ctypes.memmove(ctypes.c_void_p(self._address), source, self._size)

    @staticmethod
    def _make_readonly_view(data) -> memoryview:
        """Return a read-only byte-typed memoryview over the given buffer."""
        view = memoryview(data)
        if view.format != "B":
            view = view.cast("B")
        return view.toreadonly()

    def _lock_memory(self) -> None:
        """Lock memory using platform-specific API."""
        if not _kernel32:
            raise SecureMemoryError("Windows secure memory APIs are unavailable")

        if not _kernel32.VirtualLock(
            ctypes.c_void_p(self._address), ctypes.c_size_t(self._alloc_size)
        ):
            error_code = ctypes.get_last_error()
            raise SecureMemoryError(f"VirtualLock failed: {error_code}")
        self._locked = True

    def _unlock_memory(self) -> None:
        """Unlock memory using platform-specific API."""
        if not self._locked:
            return

        if not _kernel32:
            return

        _kernel32.VirtualUnlock(
            ctypes.c_void_p(self._address), ctypes.c_size_t(self._alloc_size)
        )
        self._locked = False

    def _free_windows_memory(self) -> None:
        """Release the VirtualAlloc region back to the OS."""
        if _PLATFORM != "Windows" or not _kernel32 or not self._address:
            return

        _kernel32.VirtualFree(
            ctypes.c_void_p(self._address), ctypes.c_size_t(0), _WIN_MEM_RELEASE
        )
        self._address = 0
        self._alloc_size = 0

    def view(self) -> memoryview:
        """Return a read-only view over the sensitive data."""
        if self.is_cleared:
            raise ValueError("Cannot access cleared secure bytes")
        if self._view is None:
            raise ValueError("Secure bytes are not initialized")
        return self._view

    def get(self) -> bytes:
        """Return a temporary bytes copy of the sensitive data."""
        return bytes(self.view())

    def clear(self) -> None:
        """Securely zero out the memory and release the OS lock."""
        if self.is_cleared:
            return

        try:
            if self._address and self._alloc_size:
                ctypes.memset(ctypes.c_void_p(self._address), 0, self._alloc_size)
        finally:
            if self._view is not None:
                self._view.release()
                self._view = None
            self._unlock_memory()
            self._free_windows_memory()
            self.is_cleared = True
            logger.debug("SecureMemory cleared and unlocked")

    @staticmethod
    def secure_zero(data: bytearray) -> None:
        """Overwrite a bytearray with zeros."""
        logger.debug("Attempting to zero out master key")
        for i in range(len(data)):
            data[i] = 0

    def __enter__(self):
        """Return self for use as a context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clear secure memory on context manager exit."""
        self.clear()
        return False

    def __del__(self):
        """Clear secure memory if not already cleared on garbage collection."""
        try:
            if getattr(self, "is_cleared", True) is False:
                self.clear()
        except Exception as e:
            logger.warning(f"Error in __del__ SecureMemory : {e}")
