import ctypes

import pytest

from app.core.crypto.primitives import secure_memory as sm
from app.core.crypto.primitives.secure_memory import SecureMemory
from app.exceptions.crypto import SecureMemoryError


def _arg_value(value):
    return value.value if hasattr(value, "value") else value


class FakeKernel32:
    def __init__(self, *, page_size=4096, fail_alloc=False, fail_lock=False):
        self.page_size = page_size
        self.fail_alloc = fail_alloc
        self.fail_lock = fail_lock
        self.lock_calls = []
        self.unlock_calls = []
        self.free_calls = []
        self.free_snapshots = {}
        self._regions = {}

    def GetSystemInfo(self, info_ptr):
        info_ptr._obj.dwPageSize = self.page_size

    def VirtualAlloc(self, _address, size, _allocation_type, _protect):
        if self.fail_alloc:
            return 0

        alloc_size = _arg_value(size)
        region = (ctypes.c_ubyte * alloc_size)()
        address = ctypes.addressof(region)
        self._regions[address] = region
        return address

    def VirtualLock(self, address, size):
        raw_address = _arg_value(address)
        raw_size = _arg_value(size)
        self.lock_calls.append((raw_address, raw_size))
        if self.fail_lock:
            return 0
        return 1

    def VirtualUnlock(self, address, size):
        self.unlock_calls.append((_arg_value(address), _arg_value(size)))
        return 1

    def VirtualFree(self, address, _size, _free_type):
        raw_address = _arg_value(address)
        self.free_calls.append(raw_address)
        region = self._regions.pop(raw_address, None)
        if region is not None:
            self.free_snapshots[raw_address] = bytes(region)
        return 1


def _install_fake_windows(monkeypatch, fake_kernel32, *, last_error=1):
    monkeypatch.setattr(sm, "_PLATFORM", "Windows")
    monkeypatch.setattr(sm, "_kernel32", fake_kernel32)
    monkeypatch.setattr(sm.ctypes, "get_last_error", lambda: last_error)


class TestSecureMemory:
    def test_lifecycle(self):
        secret = b"glyphweave_master_key"
        mem = SecureMemory(secret)

        view = mem.view()
        assert isinstance(view, memoryview)
        assert view.tobytes() == secret
        assert mem.get() == secret
        assert mem.is_cleared is False

        assert mem._alloc_size >= len(secret)
        assert mem._alloc_size % mem._page_size == 0

        mem.clear()
        assert mem.is_cleared is True

        assert mem._address == 0
        assert mem._alloc_size == 0

        with pytest.raises(ValueError, match="Cannot access cleared secure bytes"):
            mem.get()

        with pytest.raises(ValueError, match="Cannot access cleared secure bytes"):
            mem.view()

    def test_context_manager(self):
        secret = b"context_secret"
        with SecureMemory(secret) as mem:
            assert mem.view().tobytes() == secret
            assert mem.get() == secret
            assert not mem.is_cleared

        assert mem.is_cleared is True

    def test_secure_zero_static(self):
        data = bytearray(b"sensitive_data")
        SecureMemory.secure_zero(data)
        assert data == bytearray(len(data))
        assert all(b == 0 for b in data)

    def test_large_data(self):
        large_secret = b"x" * 8193
        mem = SecureMemory(large_secret)
        assert mem.get() == large_secret
        mem.clear()
        assert mem.is_cleared is True

    def test_consume_mutable_zeros_source(self):
        source = bytearray(b"sensitive_source")
        mem = SecureMemory.consume_mutable(source)
        assert mem.get() == b"sensitive_source"
        assert source == bytearray(len(source))
        mem.clear()

    def test_windows_backend_uses_page_sized_allocation(self, monkeypatch):
        fake = FakeKernel32(page_size=4096)
        _install_fake_windows(monkeypatch, fake)

        mem = SecureMemory(b"secret")
        address, alloc_size = fake.lock_calls[0]
        assert mem.get() == b"secret"
        assert mem._size == 6
        assert mem._page_size == 4096
        assert mem._alloc_size == 4096
        assert alloc_size == 4096
        assert address == mem._address

        mem.clear()
        assert fake.unlock_calls == [(address, 4096)]
        assert fake.free_snapshots[address] == b"\x00" * 4096

    def test_windows_backend_rounds_multi_page_allocations(self, monkeypatch):
        fake = FakeKernel32(page_size=4096)
        _install_fake_windows(monkeypatch, fake)

        mem = SecureMemory(b"x" * 8193)
        address, alloc_size = fake.lock_calls[0]
        assert mem._size == 8193
        assert mem._alloc_size == 12288
        assert alloc_size == 12288

        mem.clear()
        assert fake.free_snapshots[address] == b"\x00" * 12288

    def test_windows_allocate_failure_raises(self, monkeypatch):
        fake = FakeKernel32(fail_alloc=True)
        _install_fake_windows(monkeypatch, fake, last_error=1455)

        with pytest.raises(SecureMemoryError, match="VirtualAlloc failed: 1455"):
            SecureMemory(b"secret")

    def test_windows_lock_failure_frees_partial_allocation(self, monkeypatch):
        fake = FakeKernel32(fail_lock=True)
        _install_fake_windows(monkeypatch, fake, last_error=1455)

        with pytest.raises(SecureMemoryError, match="VirtualLock failed: 1455"):
            SecureMemory(b"secret")

        assert len(fake.free_calls) == 1
        freed_address = fake.free_calls[0]
        assert fake.free_snapshots[freed_address] == b"\x00" * fake.page_size

    def test_consume_mutable_zeros_source_on_failure(self, monkeypatch):
        fake = FakeKernel32(fail_alloc=True)
        _install_fake_windows(monkeypatch, fake, last_error=8)
        source = bytearray(b"secret")

        with pytest.raises(SecureMemoryError, match="VirtualAlloc failed: 8"):
            SecureMemory.consume_mutable(source)

        assert source == bytearray(len(source))

    def test_non_windows_platform_is_rejected(self, monkeypatch):
        monkeypatch.setattr(sm, "_PLATFORM", "Linux")
        monkeypatch.setattr(sm, "_kernel32", None)

        with pytest.raises(
            SecureMemoryError, match="SecureMemory is only supported on Windows"
        ):
            SecureMemory(b"secret")
