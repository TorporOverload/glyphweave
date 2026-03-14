from __future__ import annotations

from pathlib import Path

from app.config import ensure_app_data_layout
from app.core.service.models import VaultContext
from app.core.service.registry_service import APP_DATA_DIR
from app.core.service.vault_file_service import VaultFileService
from app.core.service.vault_runtime_service import VaultRuntimeService
from app.core.crypto.types import KDFParams


class VaultService:
    def __init__(self, app_data_dir: Path | None = None):
        base_dir = app_data_dir or APP_DATA_DIR
        ensure_app_data_layout(base_dir)
        self.context = VaultContext(app_data_dir=base_dir)
        self.runtime = VaultRuntimeService(self.context)
        self.files = VaultFileService(self.context)

    @property
    def vault_name(self) -> str | None:
        """Return the display name of the currently loaded vault."""
        return self.context.vault_name

    @property
    def vault_path(self) -> Path | None:
        """Return the filesystem path of the currently loaded vault."""
        return self.context.vault_path

    @property
    def db_key_hex(self) -> str | None:
        """Return the hex-encoded database encryption key."""
        return self.context.db_key_hex

    def load_known_vaults(self) -> list[dict]:
        """Return all vaults recorded in the local registry."""
        return self.runtime.load_known_vaults()

    def prepare_existing_vault(
        self,
        vault_path: Path,
        fallback_alias: str | None = None,
        fallback_vault_id: str | None = None,
    ) -> None:
        """Load an existing vault's metadata into context without unlocking it."""
        self.runtime.prepare_existing_vault(
            vault_path, fallback_alias, fallback_vault_id
        )

    def create_new_vault(
        self,
        vault_path: Path,
        vault_name: str,
        password: str,
        kdf_params: KDFParams | None = None,
    ) -> str:
        """Create a new encrypted vault and return the generated recovery phrase."""
        return self.runtime.create_new_vault(
            vault_path, vault_name, password, kdf_params
        )

    def open_existing_vault(self, password: str) -> None:
        """Unlock the prepared vault with the given password."""
        self.runtime.open_existing_vault(password)

    def recover_with_recovery_phrase(
        self,
        recovery_phrase: str,
        new_password: str,
    ) -> None:
        """Recover vault access using the recovery phrase and set a new password."""
        self.runtime.recover_with_recovery_phrase(recovery_phrase, new_password)

    def list_root_entries(self):
        """Return all top-level entries in the vault."""
        return self.files.list_root_entries()

    def list_children(self, parent_id: int):
        """Return all children of the specified folder."""
        return self.files.list_children(parent_id)

    def add_file(
        self,
        source: Path,
        dest_name: str | None = None,
        dest_parent_virtual_path: str | None = None,
    ):
        """Encrypt and import a file from the filesystem into the vault."""
        return self.files.add_file(source, dest_name, dest_parent_virtual_path)

    def open_file_by_ref(self, file_ref_id: int, launch_in_default_app: bool = True):
        """Open a vault file by its reference ID, optionally launching it in the default
        app."""
        return self.files.open_file_by_ref(file_ref_id, launch_in_default_app)

    def list_unlocked_files(self):
        """Return all currently unlocked vault files."""
        return self.files.list_unlocked_files()

    def reopen_unlocked(self, file_ref_id: int) -> str:
        """Re-launch an already-unlocked file in the default application."""
        return self.files.reopen_unlocked(file_ref_id)

    def unmount_unlocked(self, file_ref_id: int) -> str:
        """Unmount or finalize an unlocked file and save any changes back to the
        vault."""
        return self.files.unmount_unlocked(file_ref_id)

    def get_db_debug_info(self) -> dict:
        """Return debug information about the vault database."""
        return self.files.get_db_debug_info()

    def get_recovery_phrase(self) -> str:
        """Return the vault's recovery phrase."""
        return self.files.get_recovery_phrase()

    def cleanup(self) -> None:
        """Finalize all open files and release vault resources."""
        self.files.cleanup()
