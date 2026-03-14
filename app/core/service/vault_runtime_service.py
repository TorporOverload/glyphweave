from __future__ import annotations

import uuid
from pathlib import Path

from app.core.crypto.service.key_service import KeyService
from app.core.crypto.service.utils import load_vault_key, save_vault_key
from app.core.crypto.types import KDFParams, VaultKeyFile, WrappedKey
from app.core.vault_layout import (
    ensure_vault_layout,
    metadata_path,
    vault_key_path,
)

from .models import VaultContext
from .registry_service import (
    load_registry,
    upsert_registry,
    write_vault_metadata,
)
from .vault_runtime_bootstrap import bootstrap_runtime_services
from .vault_runtime_state import (
    assign_vault_location,
    attach_unlocked_key_service,
    ensure_local_runtime_dirs,
    prepare_existing_vault_context,
)


class VaultRuntimeService:
    def __init__(self, context: VaultContext):
        self.context = context

    def load_known_vaults(self) -> list[dict]:
        """Return the list of all registered vaults from the registry."""
        return load_registry()

    def prepare_existing_vault(
        self,
        vault_path: Path,
        fallback_alias: str | None = None,
        fallback_vault_id: str | None = None,
    ) -> None:
        """Load an existing vault's metadata into context without unlocking it."""
        prepare_existing_vault_context(
            self.context,
            vault_path,
            fallback_alias,
            fallback_vault_id,
        )

    def create_new_vault(
        self,
        vault_path: Path,
        vault_name: str,
        password: str,
        kdf_params: KDFParams | None = None,
    ) -> str:
        """Create a new vault, generate keys, and return the recovery phrase."""
        if metadata_path(vault_path).exists():
            raise FileExistsError("A vault already exists in that directory")

        if kdf_params is None:
            kdf_params = KDFParams()

        vault_id = str(uuid.uuid4())
        assign_vault_location(
            self.context,
            vault_path=vault_path,
            vault_id=vault_id,
            vault_name=vault_name,
        )

        ensure_vault_layout(vault_path)
        if self.context.local_data_path is None:
            raise RuntimeError("Local data path is not set")
        ensure_local_runtime_dirs(self.context.local_data_path)

        write_vault_metadata(vault_path, vault_id, vault_name)

        key_service = KeyService()
        key_service.generate_master_key()

        dummy_wrapped = WrappedKey(
            ciphertext=b"\x00" * 40,
            salt=b"\x00" * 16,
            kdf_params=kdf_params,
        )
        key_service.vault_key_file = VaultKeyFile(
            password_wrapped=dummy_wrapped,
            recovery_wrapped=dummy_wrapped,
            recovery_phrase_wrapped=b"\x00" * 40,
            check_nonce=b"\x00" * 16,
            check_value=b"\x00" * 32,
            vault_id=vault_id,
        )

        key_service.wrap_master_key(password, kdf_params)
        recovery_phrase = key_service.generate_recovery_phrase()
        key_service.wrap_recovery_key(recovery_phrase, kdf_params)
        key_service.wrap_recovery_phrase_with_master(recovery_phrase)
        save_vault_key(key_service.vault_key_file, vault_key_path(vault_path))

        attach_unlocked_key_service(
            self.context,
            vault_id=vault_id,
            key_service=key_service,
        )

        self._init_services()
        upsert_registry(vault_id, vault_name, str(vault_path))
        return recovery_phrase

    def open_existing_vault(self, password: str) -> None:
        """Unlock an existing vault with the given password and initialize all
        services."""
        vault_path = self.context.require_vault_path()
        ensure_vault_layout(vault_path)
        key_path = vault_key_path(vault_path)
        if not key_path.exists():
            raise FileNotFoundError(f"vault.key not found at {key_path}")

        key_service = KeyService()
        key_service.vault_key_file = load_vault_key(key_path)
        key_service.unwrap_master_key(password)

        vault_id = key_service.vault_key_file.vault_id
        attach_unlocked_key_service(
            self.context,
            vault_id=vault_id,
            key_service=key_service,
        )

        self._init_services()
        upsert_registry(
            vault_id,
            self.context.vault_name or vault_path.name,
            str(vault_path),
        )

    def recover_with_recovery_phrase(
        self,
        recovery_phrase: str,
        new_password: str,
    ) -> None:
        """Reset the vault password using the recovery phrase and unlock the vault."""
        vault_path = self.context.require_vault_path()
        ensure_vault_layout(vault_path)
        key_path = vault_key_path(vault_path)
        if not key_path.exists():
            raise FileNotFoundError(f"vault.key not found at {key_path}")

        key_service = KeyService()
        key_service.vault_key_file = load_vault_key(key_path)
        key_service.unwrap_with_recovery_phrase(recovery_phrase)
        key_service.wrap_recovery_phrase_with_master(recovery_phrase)

        kdf_params = key_service.vault_key_file.password_wrapped.kdf_params
        key_service.wrap_master_key(new_password, kdf_params)
        save_vault_key(key_service.vault_key_file, key_path)

        vault_id = key_service.vault_key_file.vault_id
        attach_unlocked_key_service(
            self.context,
            vault_id=vault_id,
            key_service=key_service,
        )

        self._init_services()
        upsert_registry(
            vault_id,
            self.context.vault_name or vault_path.name,
            str(vault_path),
        )

    def _init_services(self) -> None:
        """Bootstrap all runtime services for the currently loaded vault context."""
        bootstrap_runtime_services(self.context)
