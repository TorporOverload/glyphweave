import pytest

from app.infrastructure.crypto.primitives.key_derivation import (
    derive_kek_from_password,
    derive_subkey,
)
from app.infrastructure.crypto.types import KeyPurpose


class TestDeriveKekFromPassword:
    def test_derives_key_with_valid_password(self) -> None:
        from app.infrastructure.crypto.types import KDFParams

        params = KDFParams(
            algorithm="argon2id",
            salt_size=16,
            iterations=1,
            parallelism=1,
            memory_kb=8192,
            length=32,
        )
        key, salt = derive_kek_from_password("test_password", params)

        assert isinstance(key, bytearray)
        assert len(key) == 32
        assert isinstance(salt, bytes)
        assert len(salt) == 16

    def test_returns_same_key_with_same_salt(self) -> None:
        from app.infrastructure.crypto.types import KDFParams

        params = KDFParams(
            algorithm="argon2id",
            salt_size=16,
            iterations=1,
            parallelism=1,
            memory_kb=8192,
            length=32,
        )
        salt = b"fixed_salt_16byte"
        key1, _ = derive_kek_from_password("password", params, salt=salt)
        key2, _ = derive_kek_from_password("password", params, salt=salt)

        assert key1 == key2

    def test_different_passwords_different_keys(self) -> None:
        from app.infrastructure.crypto.types import KDFParams

        params = KDFParams(
            algorithm="argon2id",
            salt_size=16,
            iterations=1,
            parallelism=1,
            memory_kb=8192,
            length=32,
        )
        salt = b"fixed_salt_16byte"
        key1, _ = derive_kek_from_password("password1", params, salt=salt)
        key2, _ = derive_kek_from_password("password2", params, salt=salt)

        assert key1 != key2


class TestDeriveSubkey:
    def test_derives_subkey_for_file_purpose(self) -> None:
        master_key = b"0" * 32
        vault_id = b"vault-1"

        subkey = derive_subkey(master_key, vault_id, KeyPurpose.FILE, "file-1")

        assert isinstance(subkey, bytearray)
        assert len(subkey) == 32

    def test_derives_subkey_for_database_purpose(self) -> None:
        master_key = b"0" * 32
        vault_id = b"vault-1"

        subkey = derive_subkey(master_key, vault_id, KeyPurpose.DATABASE, "db-1")

        assert isinstance(subkey, bytearray)
        assert len(subkey) == 32

    def test_derives_subkey_for_event_purpose(self) -> None:
        master_key = b"0" * 32
        vault_id = b"vault-1"

        subkey = derive_subkey(master_key, vault_id, KeyPurpose.EVENT, "event-1")

        assert isinstance(subkey, bytearray)
        assert len(subkey) == 32

    def test_different_contexts_produce_different_keys(self) -> None:
        master_key = b"0" * 32
        vault_id = b"vault-1"

        subkey1 = derive_subkey(master_key, vault_id, KeyPurpose.FILE, "file-1")
        subkey2 = derive_subkey(master_key, vault_id, KeyPurpose.FILE, "file-2")

        assert subkey1 != subkey2

    def test_different_vault_ids_produce_different_keys(self) -> None:
        master_key = b"0" * 32

        subkey1 = derive_subkey(master_key, b"vault-1", KeyPurpose.FILE, "file-1")
        subkey2 = derive_subkey(master_key, b"vault-2", KeyPurpose.FILE, "file-1")

        assert subkey1 != subkey2

    def test_raises_on_none_purpose(self) -> None:
        master_key = b"0" * 32

        with pytest.raises(AttributeError):
            derive_subkey(master_key, b"vault-1", None, "context")
