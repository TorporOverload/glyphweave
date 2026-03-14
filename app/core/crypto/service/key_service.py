import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mnemonic import Mnemonic

from app.core.crypto.constants import CHECK_PLAINTEXT, MASTER_KEY_SIZE
from app.core.crypto.primitives.key_derivation import (
    derive_kek_from_password,
    derive_subkey,
)
from app.core.crypto.primitives.key_wrapping import unwrap_key, wrap_key
from app.core.crypto.primitives.secure_memory import SecureMemory
from app.core.crypto.types import KDFParams, KeyPurpose, VaultKeyFile, WrappedKey
from app.exceptions.crypto import InvalidPasswordError
from app.utils.logging import logger, timed_operation


class KeyService:
    """Service for key generation, wrapping, and unwrapping operations."""

    def __init__(self):
        self.master_key: None | SecureMemory = None
        self.vault_key_file: VaultKeyFile

    # Master Key Operations
    @timed_operation("generate_master_key")
    def generate_master_key(self):
        """
        Generate a secure random master key.
        """
        logger.debug("Generating new master key.")
        self.master_key = SecureMemory(secrets.token_bytes(MASTER_KEY_SIZE))

    @timed_operation("wrap_master_key")
    def wrap_master_key(self, password: str, kdf_params: KDFParams) -> None:
        """
        Wrap a master key with a Key Encryption Key derived from a password.
        Stores the result in self.vault_key_file.password_wrapped.

        Args:
            password: User password for KEK derivation
            kdf_params: Argon2id parameters for key derivation
        """

        logger.debug("Wrapping master key.")
        kek_password, salt = derive_kek_from_password(password, kdf_params)

        check_nonce = secrets.token_bytes(16)
        cipher = AESGCM(kek_password)
        check_cipher = cipher.encrypt(
            check_nonce, CHECK_PLAINTEXT, associated_data=None
        )

        if not self.master_key:
            logger.error("Master key is not initialized.")
            raise ValueError("Master key is not initialized.")

        # Wrap master key using AES Key Wrap
        wrapped_key = wrap_key(kek_password, self.master_key.view())

        # Store in vault_key_file
        self.vault_key_file.password_wrapped = WrappedKey(
            ciphertext=wrapped_key, salt=salt, kdf_params=kdf_params
        )
        self.vault_key_file.check_nonce = check_nonce
        self.vault_key_file.check_value = check_cipher

        logger.debug("Master key wrapped successfully.")

    @timed_operation("unwrap_master_key")
    def unwrap_master_key(self, password: str) -> None:
        """
        Unwrap a master key using a Key Encryption Key derived from a password.
        Reads wrapped key data from self.vault_key_file.

        Args:
            password: User password for KEK derivation

        Raises:
            InvalidPasswordError: If the password is incorrect
        """

        logger.debug("Unwrapping master key.")
        wrapped_key = self.vault_key_file.password_wrapped

        kek_password, _ = derive_kek_from_password(
            password, wrapped_key.kdf_params, salt=wrapped_key.salt
        )

        cipher = AESGCM(kek_password)
        try:
            cipher.decrypt(
                self.vault_key_file.check_nonce,
                self.vault_key_file.check_value,
                associated_data=None,
            )
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

    def wrap_recovery_key(self, recovery_phrase: str, kdf_params: KDFParams) -> None:
        """
        Wrap the master key using a KEK derived from the recovery phrase.
        Stores the result in self.vault_key_file.recovery_wrapped.

        Args:
            recovery_phrase: The BIP39 recovery phrase.
            kdf_params: Argon2id parameters for key derivation.
        """

        logger.debug("Wrapping master key with recovery phrase.")

        # Derive recovery key from recovery phrase
        recovery_seed = Mnemonic("english").to_seed(recovery_phrase)[:32]
        kek_recovery, salt = derive_kek_from_password(recovery_seed.hex(), kdf_params)

        if not self.master_key:
            logger.error("Master key is not initialized.")
            raise ValueError("Master key is not initialized.")

        # Wrap master key using AES Key Wrap
        wrapped_key = wrap_key(kek_recovery, self.master_key.view())

        # Store in vault_key_file
        self.vault_key_file.recovery_wrapped = WrappedKey(
            ciphertext=wrapped_key, salt=salt, kdf_params=kdf_params
        )

        logger.debug("Master key wrapped with recovery phrase successfully.")

    def unwrap_with_recovery_phrase(self, recovery_phrase: str) -> None:
        """
        Unwrap the master key using a recovery phrase.

        Args:
            recovery_phrase: The BIP39 recovery phrase.

        Raises:
            ValueError: If the recovery phrase is invalid.
        """

        logger.debug("Recovering master key from recovery phrase.")

        if not self.validate_recovery_phrase(recovery_phrase):
            logger.error("Invalid recovery phrase provided.")
            raise ValueError("Invalid recovery phrase format")

        wrapped_key = self.vault_key_file.recovery_wrapped

        # Derive KEK from recovery phrase
        recovery_seed = Mnemonic("english").to_seed(recovery_phrase)[:32]
        kek_recovery, _ = derive_kek_from_password(
            recovery_seed.hex(), wrapped_key.kdf_params, salt=wrapped_key.salt
        )

        try:
            # Unwrap master key using AES Key Wrap
            self.master_key = SecureMemory(
                unwrap_key(kek_recovery, wrapped_key.ciphertext)
            )
            logger.info("Master key recovered from recovery phrase.")
        except Exception as e:
            logger.error(f"Failed to recover key from phrase: {e}")
            raise ValueError(f"Failed to recover key from phrase: {e}") from e

    def wrap_recovery_phrase_with_master(self, recovery_phrase: str) -> None:
        """Store a master-key-wrapped copy of the recovery phrase."""
        if not self.master_key:
            logger.error("Master key is not initialized.")
            raise ValueError("Master key is not initialized.")

        self.vault_key_file.recovery_phrase_wrapped = wrap_key(
            self.master_key.view(), recovery_phrase.encode("utf-8")
        )

    def unwrap_recovery_phrase_with_master(self) -> str:
        """Return the recovery phrase by decrypting it with the master key."""
        if not self.master_key:
            logger.error("Master key is not initialized.")
            raise ValueError("Master key is not initialized.")
        if not self.vault_key_file.recovery_phrase_wrapped:
            raise ValueError("Recovery phrase is not available for this vault")

        phrase_bytes = unwrap_key(
            self.master_key.view(), self.vault_key_file.recovery_phrase_wrapped
        )
        return phrase_bytes.decode("utf-8")

    def derive_database_key(self) -> str:
        """Derives the vault db key for sqlcipher database.
        Returns: 64 Hex characters
        """

        if not self.master_key:
            logger.error("Master key is not initialized.")
            raise ValueError("Master key is not initialized.")

        db_key = derive_subkey(
            self.master_key.view(),
            self.vault_key_file.vault_id.encode("utf-8"),
            KeyPurpose.DATABASE,
            "vault_db_master_key",
        )
        logger.debug("Database key derived successfully.")
        return db_key.hex()

    def derive_sub_key(self, purpose: KeyPurpose, context: str) -> bytes:
        """Derives a subkey for a given purpose and context.

        Args:
            purpose (KeyPurpose): The purpose of the subkey.
            context (str): The context for the subkey (id of the file, etc...).

        Returns:
            bytes: The derived subkey.
        """
        if not self.master_key:
            logger.error("Master key is not initialized.")
            raise ValueError("Master key is not initialized.")

        file_key = derive_subkey(
            self.master_key.view(),
            self.vault_key_file.vault_id.encode("utf-8"),
            purpose,
            context,
        )
        logger.debug(f"subkey derived for {purpose} :: {context} successfully.")
        return file_key

    @staticmethod
    @timed_operation("validate_recovery_phrase")
    def validate_recovery_phrase(phrase: str) -> bool:
        """
        Validate a recovery format.

        Args:
            phrase: The recovery phrase to validate

        Returns: True if valid, False otherwise
        """
        logger.debug("Validating recovery phrase format.")
        try:
            words = phrase.strip().split()

            if len(words) != 24:
                logger.warning(f"Invalid recovery phrase word count: {len(words)}")
                return False
            logger.debug("Recovery phrase format is valid.")
            return True
        except Exception as e:
            logger.error(f"Error validating recovery phrase: {e}")
            return False
