import pytest

from app.core.crypto.primitives.secure_memory import SecureMemory


class TestSecureMemory:
    def test_lifecycle(self):
        """Test initialization, get, and clearing of SecureMemory."""
        secret = b"glyphweave_master_key"
        mem = SecureMemory(secret)

        # Test get
        assert mem.get() == secret
        assert mem.is_cleared is False

        # Test internal storage
        assert mem._data == bytearray(secret)

        # Test clear
        mem.clear()
        assert mem.is_cleared is True
        assert mem._data == bytearray(len(secret))  # Should be zeroed

        # Test access after clear
        with pytest.raises(ValueError, match="Cannot access cleared secure bytes"):
            mem.get()

    def test_context_manager(self):
        """Test usage as a context manager."""
        secret = b"context_secret"
        with SecureMemory(secret) as mem:
            assert mem.get() == secret
            assert not mem.is_cleared

        # Should be cleared after exit
        assert mem.is_cleared is True
        assert mem._data == bytearray(len(secret))

    def test_secure_zero_static(self):
        """Test the static secure_zero method."""
        data = bytearray(b"sensitive_data")
        SecureMemory.secure_zero(data)
        assert data == bytearray(len(data))
        assert all(b == 0 for b in data)

    def test_large_data(self):
        """Test with larger data chunk."""
        # 1MB of data
        large_secret = b"x" * 1024 * 1024
        mem = SecureMemory(large_secret)
        assert mem.get() == large_secret
        mem.clear()
        assert mem._data == bytearray(1024 * 1024)
