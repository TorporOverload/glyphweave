from __future__ import annotations

from app.common.config import is_event_encryption_enabled
from app.infrastructure.persistence.event_store import EventStore
from app.infrastructure.persistence.event_store_config import EventStoreConfig
from app.services.models import VaultContext


def build_event_store(context: VaultContext) -> EventStore:
    existing = context.event_store
    if existing is not None:
        return existing

    store = EventStore(
        EventStoreConfig(
            vault_path=context.require_vault_path(),
            vault_id=context.require_vault_id(),
            master_key=context.require_master_key(),
            encryption_enabled=is_event_encryption_enabled(),
        )
    )
    context.event_store = store
    return store
