"""Recovery and backup management service."""

from app.core.crypto.services.key_service import KeyService
from app.utils.logging import logger, timed_operation


class RecoveryService:
    def __init__(self):
        self.key_service = KeyService()

    @timed_operation("generate_recovery_key")
    def generate_recovery_key(self) -> str:
        """
        Generate a recovery key (BIP39 24-word mnemonic).
        Returns: Space-separated recovery phrase
        """
        logger.debug("Generating new recovery key.")
        return self.key_service.generate_recovery_phrase()

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

    @timed_operation("recover_from_phrase")
    def recover_from_phrase(self, recovery_phrase: str):
        """
        Derive a master key from a recovery phrase.

        Args:
            recovery_phrase: The BIP39 recovery phrase

        Returns: Derived master key (32 bytes)

        Raises:
            ValueError: If phrase is invalid
        """
        self.key_service._recover_from_phrase(recovery_phrase)
        