import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mnemonic import Mnemonic

from app.core.crypto.constants import MASTER_KEY_SIZE, CHECK_PLAINTEXT
from app.core.crypto.primitives.key_derivation import (
    derive_kek_from_password,
    derive_subkey,
)
from app.core.crypto.primitives.key_wrapping import unwrap_key, wrap_key
from app.core.crypto.primitives.secure_memory import SecureMemory
from app.core.crypto.types import KDFParams, KeyPurpose, WrappedKey
from app.utils.logging import logger, timed_operation
from app.core.crypto.services.recovery_service import RecoveryService
from app.exceptions.crypto import InvalidPasswordError


class KeyService:
    """Service for key generation, wrapping, and unwrapping operations."""

    def __init__(self):
        self.master_key: None | SecureMemory

    # Master Key Operations
    @timed_operation("generate_master_key")
    def generate_master_key(self):
        """
        Generate a secure random master key.
        """
        logger.debug("Generating new master key.")
        self.master_key = SecureMemory(secrets.token_bytes(MASTER_KEY_SIZE))

    @timed_operation("wrap_master_key")
    def wrap_master_key(self, password: str, 
        kdf_params: KDFParams) -> tuple[WrappedKey, bytes, bytes]:
        """
        Wrap a master key with a Key Encryption Key derived from a password.

        Args:
            master_key: The master key to wrap
            password: User password for KEK derivation
            kdf_params: Argon2id parameters for key derivation

        Returns: (wrapped_key, check_nonce, check_value)
                 check_nonce, check_value are used to validate the password before doing a full unrap of the password to ensure it is correct
        """ # noqa: E501
        
        logger.debug("Wrapping master key.")
        kek_password, salt = derive_kek_from_password(password, kdf_params)
        
        check_nonce = secrets.token_bytes(16)
        cipher = AESGCM(kek_password)
        check_cipher = cipher.encrypt(check_nonce, 
            CHECK_PLAINTEXT , associated_data=None)

        # Wrap master key using AES Key Wrap
        if not self.master_key:
            raise ValueError("Master key not initialized.")

        wrapped_key = wrap_key(kek_password, self.master_key.get())
        logger.debug("Master key wrapped successfully.")
        return (WrappedKey(ciphertext=wrapped_key, salt=salt, kdf_params=kdf_params),
                check_nonce, check_cipher)

    @timed_operation("unwrap_master_key")
    def unwrap_master_key(self, wrapped_key: WrappedKey, password: str,
        check_nonce: bytes, check_cipher: bytes):
        """
        Unwrap a master key using a Key Encryption Key derived from a password.
        Args:
            wrapped_key: WrappedKey object containing ciphertext and metadata
            password: User password for KEK derivation
            check_nonce: Nonce used for check_cipher
            check_chiper: encrypted CHECK_PLAINTEXT using AESGCM Cipher

        Returns: Unwrapped master key
        Raises:
            InvalidPasswordError: If the password is incorrect
        """
        logger.debug("Unwrapping master key.")
        kek_password, _ = derive_kek_from_password(
            password, wrapped_key.kdf_params, salt=wrapped_key.salt
        )
        
        cipher = AESGCM(kek_password)
        try:
            cipher.decrypt(check_nonce, check_cipher, associated_data=None)
        except Exception as e:
            logger.error(f"Failed to decrypt check value: {e}")
            raise InvalidPasswordError("Incorrect password/recovery key")
        
        # Unwrap master key using AES Key Wrap
        self.master_key = SecureMemory(unwrap_key(kek_password, wrapped_key.ciphertext))
        logger.debug("Master key unwrapped successfully.")

    # Recovery key Operations
    @timed_operation("generate_recovery_phrase")
    def generate_recovery_phrase(self) -> str:
        """
        Generate a 24-word BIP39 mnemonic recovery phrase.

        Returns: Space-separated recovery phrase (256-bit entropy)
        """
        logger.debug("Generating new recovery phrase.")
        mnemo = Mnemonic("english")
        words = mnemo.generate(strength=256)
        logger.debug("Recovery phrase generated.")
        return words
        
    def wrap_recovery_key(self, recovery_key: str) -> bytes:
        """
        Wrap a recovery key using AES Key Wrap.
        Args:
            recovery_key (str): The recovery key to wrap.
        Returns:
            bytes: The wrapped recovery key.
        """
        logger.debug("Wrapping recovery key.")
        if not self.master_key:
            raise ValueError("Master key not initialized.")
        wrapped_key = wrap_key(self.master_key.get(), recovery_key.encode('utf-8'))
        logger.debug("Recovery key wrapped successfully.")
        return wrapped_key
        
    def unwrap_recovery_key(self, wrapped_key: bytes) -> str:
        """
        Unwrap a recovery key using AES Key Wrap.
        Args:
            wrapped_key (bytes): The wrapped recovery key.
        Returns:
            str: The unwrapped recovery key.
        """
        logger.debug("Unwrapping recovery key.")
        if not self.master_key:
            raise ValueError("Master key not initialized.")
        unwrapped_key = unwrap_key(self.master_key.get(), wrapped_key)
        logger.debug("Recovery key unwrapped successfully.")
        return unwrapped_key.decode('utf-8')

    def derive_database_key(self, vault_id: bytes) -> str:
        """Derives the vault db key for sqlciper database

        Retruns: 64 Hex characters"""
        
        if not self.master_key:
            raise ValueError("Master key not initialized.")

        db_key = derive_subkey(
            self.master_key.get(), vault_id, KeyPurpose.DATABASE, "vault_db_master_key"
        )
        logger.debug("Database key derived successfully.")
        return db_key.hex()

    def derive_sub_key(self, vault_id: bytes, purpose: KeyPurpose, 
        context: str) -> bytes:
        """Derives a subkey for a given purpose and context.

        Args:
            vault_id (bytes): The ID of the vault.
            purpose (KeyPurpose): The purpose of the subkey.
            context (str): The context for the subkey (id of the file, etc...).

        Returns:
            bytes: The derived subkey.
        """
        
        if not self.master_key:
            raise ValueError("Master key not initialized.")

        file_key = derive_subkey(self.master_key.get(), vault_id, purpose, context)
        logger.debug(f"subeky key derived for {purpose} :: {context} successfully.")
        return file_key
        
    def _recover_from_phrase(self, recovery_phrase: str):
        logger.debug("Recovering master key from recovery phrase.")

        if not RecoveryService.validate_recovery_phrase(recovery_phrase):
            logger.error("Invalid recovery phrase provided.")
            raise ValueError("Invalid recovery phrase format")

        # Convert mnemonic to seed (uses BIP39 standard)
        from mnemonic import Mnemonic

        mnemo = Mnemonic("english")
        try:
            self.master_key = SecureMemory(mnemo.to_seed(recovery_phrase)[:32])
            logger.info("Master key recovered from recovery phrase.")
            
        except Exception as e:
            logger.error(f"Failed to recover key from phrase: {e}")
            raise ValueError(f"Failed to recover key from phrase: {e}") from e
