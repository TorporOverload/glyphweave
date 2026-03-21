import pytest

from app.core.crypto.service import KeyService
from app.core.crypto.types import KDFParams, KeyPurpose, VaultKeyFile, WrappedKey
from app.exceptions.crypto import InvalidPasswordError


class TestKeyService:
    @pytest.fixture
    def service(self):
        svc = KeyService()
        # Initialize vault_key_file with placeholder values
        dummy_wrapped = WrappedKey(
            ciphertext=b"\x00" * 40,
            salt=b"\x00" * 16,
            kdf_params=KDFParams(),
        )

        svc.vault_key_file = VaultKeyFile(
            password_wrapped=dummy_wrapped,
            recovery_wrapped=dummy_wrapped,
            check_nonce=b"\x00" * 16,
            check_value=b"\x00" * 32,
            vault_id="test_vault",
            recovery_phrase_wrapped=b"\x00" * 64,
        )
        return svc

    @pytest.fixture
    def kdf_params(self):
        # Use lower cost params for faster tests
        return KDFParams(
            algorithm="Argon2id",
            length=32,
            memory_kb=1024,  # Lower memory for tests
            iterations=1,  # Lower iterations for tests
            parallelism=1,
            salt_size=16,
        )

    def test_generate_master_key(self, service):
        service.generate_master_key()
        assert service.master_key is not None

    def test_generate_recovery_phrase(self, service):
        phrase = service.generate_recovery_phrase()
        assert isinstance(phrase, str)
        words = phrase.split()
        assert len(words) == 24

    def test_wrap_and_unwrap_master_key(self, service, kdf_params):
        password = "secure_password_123"  # noqa S105
        service.generate_master_key()
        original_key = service.master_key.get()

        # Wrap - stores result in vault_key_file
        service.wrap_master_key(password, kdf_params)

        wrapped_key = service.vault_key_file.password_wrapped
        assert wrapped_key.ciphertext != original_key
        assert wrapped_key.kdf_params == kdf_params

        # Clear the master key to test unwrapping
        service.master_key = None

        # Unwrap with correct password
        service.unwrap_master_key(password)
        assert service.master_key.get() == original_key  # type: ignore[attr-defined]

    def test_unwrap_master_key_invalid_password(self, service, kdf_params):
        password = "secure_password_123"  # noqa S105
        wrong_password = "wrong_password"  # noqa S105

        service.generate_master_key()

        # Wrap master key
        service.wrap_master_key(password, kdf_params)

        # Clear the master key
        service.master_key = None

        # Unwrap with wrong password should raise InvalidPasswordError
        with pytest.raises(InvalidPasswordError):
            service.unwrap_master_key(wrong_password)

    def test_wrap_and_unwrap_recovery_key(self, service, kdf_params):
        recovery_phrase = service.generate_recovery_phrase()
        service.generate_master_key()
        original_key = service.master_key.get()

        service.wrap_recovery_key(recovery_phrase, kdf_params)
        service.master_key = None

        service.unwrap_with_recovery_phrase(recovery_phrase)
        assert service.master_key.get() == original_key  # type: ignore[attr-defined]

    def test_derive_database_and_subkey(self, service):
        service.generate_master_key()

        db_key = service.derive_database_key()
        file_key = service.derive_sub_key(KeyPurpose.FILE, "file-id-123")

        assert isinstance(db_key, str)
        assert len(db_key) == 64
        assert isinstance(file_key, bytes)
        assert len(file_key) == 32
