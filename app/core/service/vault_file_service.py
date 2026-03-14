from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.service.models import (
    AddFileResult,
    OpenFileResult,
    UnlockedFileInfo,
    VaultContext,
)
from app.core.service.vault_file_fallback import finalize_fallback_open
from app.core.service.vault_file_import import add_file as add_file_to_vault
from app.core.service.vault_file_mounts import reopen_mounted_file, unmount_mounted_file
from app.core.service.vault_file_opening import open_file_by_ref as open_file_from_vault
from app.core.service.vault_file_sessions import (
    cleanup_unlocked_files,
    list_unlocked_files as list_unlocked_file_sessions,
)

if TYPE_CHECKING:
    from app.core.crypto.service.encryption_service import EncryptionService
    from app.core.database.service.file_service import FileService
    from app.core.database.service.folder_service import FolderService


class VaultFileService:
    def __init__(self, context: VaultContext):
        self.context = context

    def list_root_entries(self):
        """Return all top-level file and folder entries in the vault."""
        folder_service = self._require_folder_service()
        return folder_service.get_root_entries()

    def list_children(self, parent_id: int):
        """Return all child entries of the given folder."""
        folder_service = self._require_folder_service()
        return folder_service.get_children(parent_id)

    def add_file(
        self,
        source,
        dest_name: str | None = None,
        dest_parent_virtual_path: str | None = None,
    ) -> AddFileResult:
        """Encrypt and import a file into the vault at the specified virtual path."""
        return add_file_to_vault(
            self.context,
            file_service=self._require_file_service(),
            folder_service=self._require_folder_service(),
            encryption_service=self._require_encryption_service(),
            source=source,
            dest_name=dest_name,
            dest_parent_virtual_path=dest_parent_virtual_path,
        )

    def open_file_by_ref(
        self,
        file_ref_id: int,
        launch_in_default_app: bool = True,
    ) -> OpenFileResult:
        """Open a vault file by reference ID, launching it in the default app if
        requested."""
        return open_file_from_vault(
            self.context,
            file_service=self._require_file_service(),
            encryption_service=self._require_encryption_service(),
            file_ref_id=file_ref_id,
            launch_in_default_app=launch_in_default_app,
        )

    def list_unlocked_files(self) -> list[UnlockedFileInfo]:
        """Return all currently unlocked files from both FUSE mounts and fallback
        cache."""
        return list_unlocked_file_sessions(self.context)

    def reopen_unlocked(self, file_ref_id: int) -> str:
        """Re-launch a currently unlocked file in the default application."""
        mounted = reopen_mounted_file(self.context, file_ref_id)
        if mounted is not None:
            return mounted

        pending = self.context.fallback_opens.get(file_ref_id)
        if pending and pending.temp_path.exists():
            from app.core.service.launcher_service import open_with_default_app

            open_with_default_app(pending.temp_path)
            return "Opened cached decrypted file"

        raise FileNotFoundError("File is not currently unlocked")

    def unmount_unlocked(self, file_ref_id: int) -> str:
        """Unmount or finalize a currently unlocked file and save any changes."""
        mounted = unmount_mounted_file(self.context, file_ref_id)
        if mounted is not None:
            return mounted

        return finalize_fallback_open(
            self.context,
            file_service=self._require_file_service(),
            folder_service=self._require_folder_service(),
            encryption_service=self._require_encryption_service(),
            file_ref_id=file_ref_id,
        )

    def cleanup(self) -> None:
        """Finalize all open files, unmount FUSE filesystems, and dispose the database
        engine."""
        cleanup_unlocked_files(
            self.context,
            file_service=self._require_file_service(),
            folder_service=self._require_folder_service(),
            encryption_service=self._require_encryption_service(),
        )

    def get_db_debug_info(self) -> dict:
        """Return debug information about the vault database path and encryption
        key."""
        local_data_path = self.context.local_data_path
        if local_data_path is None:
            raise RuntimeError("Local data path is not set")
        return {
            "db_path": local_data_path / "vault.db",
            "vault_path": self.context.vault_path,
            "db_key": self.context.db_key_hex,
        }

    def get_recovery_phrase(self) -> str:
        """Return the vault's recovery phrase by decrypting it with the master key."""
        key_service = self.context.key_service
        if not key_service or not key_service.master_key:
            raise RuntimeError("Vault is not unlocked")
        return key_service.unwrap_recovery_phrase_with_master()

    def _require_file_service(self) -> "FileService":
        """Return the file service or raise if not initialized."""
        if self.context.file_service is None:
            raise RuntimeError("File service is not initialized")
        return self.context.file_service

    def _require_folder_service(self) -> "FolderService":
        """Return the folder service or raise if not initialized."""
        if self.context.folder_service is None:
            raise RuntimeError("Folder service is not initialized")
        return self.context.folder_service

    def _require_encryption_service(self) -> "EncryptionService":
        """Return the encryption service or raise if not initialized."""
        if self.context.encryption_service is None:
            raise RuntimeError("Encryption service is not initialized")
        return self.context.encryption_service
