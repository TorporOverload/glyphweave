import pytest

from app.common.exceptions.crypto import InvalidPasswordError
from app.infrastructure.crypto.primitives.key_wrapping import (
    unwrap_key,
    wrap_key,
)


class TestWrapKey:
    def test_wraps_key_successfully(self) -> None:
        kek = b"0" * 32
        key_to_wrap = b"1" * 32

        wrapped = wrap_key(kek, key_to_wrap)

        assert isinstance(wrapped, bytes)
        assert len(wrapped) > 0
        assert wrapped != key_to_wrap

    def test_different_keys_produce_different_wrappings(self) -> None:
        kek = b"0" * 32
        key1 = b"1" * 32
        key2 = b"2" * 32

        wrapped1 = wrap_key(kek, key1)
        wrapped2 = wrap_key(kek, key2)

        assert wrapped1 != wrapped2


class TestUnwrapKey:
    def test_unwraps_key_successfully(self) -> None:
        kek = b"0" * 32
        original_key = b"1" * 32

        wrapped = wrap_key(kek, original_key)
        unwrapped = unwrap_key(kek, wrapped)

        assert unwrapped == original_key

    def test_unwrapping_with_wrong_kek_raises(self) -> None:
        kek1 = b"0" * 32
        kek2 = b"X" * 32
        key = b"1" * 32

        wrapped = wrap_key(kek1, key)

        with pytest.raises(InvalidPasswordError):
            unwrap_key(kek2, wrapped)

    def test_unwrapping_corrupted_key_raises(self) -> None:
        kek = b"0" * 32
        corrupted = b"corrupted_wrapped_key_data"

        with pytest.raises(InvalidPasswordError):
            unwrap_key(kek, corrupted)


class TestKeyWrappingRoundTrip:
    def test_wrap_unwrap_preserves_key_material(self) -> None:
        kek = b"k" * 32
        key_data = bytes(range(32))

        wrapped = wrap_key(kek, key_data)
        unwrapped = unwrap_key(kek, wrapped)

        assert unwrapped == key_data

    def test_handles_bytearray_key_material(self) -> None:
        kek = bytearray(b"0" * 32)
        key_to_wrap = bytearray(b"1" * 32)

        wrapped = wrap_key(kek, key_to_wrap)
        unwrapped = unwrap_key(kek, wrapped)

        assert unwrapped == bytes(key_to_wrap)

    def test_handles_memoryview_key_material(self) -> None:
        kek = memoryview(b"0" * 32)
        key_to_wrap = memoryview(b"1" * 32)

        wrapped = wrap_key(kek, key_to_wrap)
        unwrapped = unwrap_key(kek, wrapped)

        assert unwrapped == bytes(key_to_wrap)
