from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.infrastructure.crypto.primitives.secure_memory import SecureMemory


@dataclass(frozen=True)
class EventStoreConfig:
    vault_path: Path
    vault_id: str
    master_key: SecureMemory
    encryption_enabled: bool = True
