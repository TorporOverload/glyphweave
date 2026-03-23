from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from time import time
from typing import TYPE_CHECKING, Any

from app.infrastructure.crypto.primitives.secure_memory import SecureMemory

if TYPE_CHECKING:
    from app.infrastructure.crypto.service.encryption_service import EncryptionService
    from app.infrastructure.crypto.service.key_service import KeyService
    from app.infrastructure.persistence.db.base import DbBase
    from app.infrastructure.persistence.db.service.file_service import FileService
    from app.infrastructure.persistence.db.service.folder_service import FolderService
    from app.infrastructure.fuse.fuse_orchestrator import FuseOrchestrator
    from app.services.sync.event_emitter import EventEmitter
    from app.services.sync.runtime import EventReplayRuntime


@dataclass
class PendingFallbackOpen:
    file_ref_id: int
    file_name: str
    temp_path: Path
    original_hash: str
    original_mtime: float
    opened_at: float = field(default_factory=time)


@dataclass
class UnlockedFileInfo:
    source: str
    file_ref_id: int
    file_name: str
    file_path: Path
    opened_at: float


@dataclass
class OpenFileResult:
    opened: bool
    source: str
    file_ref_id: int
    file_name: str
    file_path: Path | None
    message: str


@dataclass
class AddFileResult:
    file_name: str
    deduplicated: bool
    file_id: str | None
    original_size: int
    encrypted_size: int
    blob_count: int
    indexed: bool = False


@dataclass
class SearchResult:
    file_ref_id: int
    file_name: str
    virtual_path: str
    snippet: str
    rank: float


@dataclass
class SearchPage:
    results: list[SearchResult]
    has_more: bool


@dataclass
class VaultContext:
    app_data_dir: Path
    vault_id: str | None = None
    vault_name: str | None = None
    vault_path: Path | None = None
    local_data_path: Path | None = None

    key_service: KeyService | None = None
    encryption_service: EncryptionService | None = None
    db: DbBase | None = None
    db_key_hex: str | None = None
    session_factory: Any = None
    file_service: FileService | None = None
    folder_service: FolderService | None = None
    mounts: FuseOrchestrator | None = None
    master_key: SecureMemory | None = None
    event_emitter: EventEmitter | None = None
    event_replay_runtime: EventReplayRuntime | None = None

    def require_vault_path(self) -> Path:
        """Return vault_path or raise RuntimeError if not set."""
        if self.vault_path is None:
            raise RuntimeError("Vault path is not set")
        return self.vault_path

    def require_vault_id(self) -> str:
        """Return vault_id or raise RuntimeError if not set."""
        if self.vault_id is None:
            raise RuntimeError("Vault ID is not set")
        return self.vault_id

    def require_master_key(self) -> SecureMemory:
        """Return master_key or raise RuntimeError if not available."""
        if self.master_key is None:
            raise RuntimeError("Master key is not available")
        return self.master_key

