from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.common.paths.vault_layout import create_vault_layout
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import HybridLogicalClock, VaultEvent
from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.infrastructure.crypto.service.encryption_service import EncryptionService
from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.model.sync_conflict import SyncConflict
from app.infrastructure.persistence.db.service.session import session_scope
from app.infrastructure.persistence.event_store import EventStore
from app.infrastructure.persistence.event_store_config import EventStoreConfig
from app.services.models import VaultContext
from app.services.sync.replay import replay_vault_events
from app.services.vault_integrity_service import VaultIntegrityService


def _store(vault_path: Path, master_key: SecureMemory) -> EventStore:
    return EventStore(
        EventStoreConfig(
            vault_path=vault_path,
            vault_id="vault-1",
            master_key=master_key,
            encryption_enabled=True,
        )
    )


def _session_factory(db_path: Path):
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


def _context(
    tmp_path: Path,
    vault_path: Path,
    session_factory,
    store: EventStore,
    master_key: SecureMemory,
) -> VaultContext:
    app_data_dir = tmp_path / "app"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    return VaultContext(
        app_data_dir=app_data_dir,
        vault_id="vault-1",
        vault_name="Test Vault",
        vault_path=vault_path,
        session_factory=session_factory,
        encryption_service=EncryptionService(),
        master_key=master_key,
        event_store=store,
    )


def _append_folder_create(
    store: EventStore,
    *,
    event_id: str,
    node_id: str,
    name: str,
    wall_time: int,
    parents: list[str] | None = None,
):
    return store.append_event(
        VaultEvent(
            event_id=event_id,
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(
                wall_time=wall_time,
                logical=0,
                device_id="device-a",
            ),
            payload={
                "node_id": node_id,
                "parent_node_id": None,
                "name": name,
            },
            parents=parents or [],
        )
    )


def _append_file_add(
    store: EventStore,
    vault_path: Path,
    master_key: SecureMemory,
    tmp_path: Path,
    *,
    event_id: str,
    node_id: str,
    file_id: str,
    name: str,
    content: bytes,
    wall_time: int,
    parents: list[str] | None = None,
):
    source_path = tmp_path / f"{event_id}.bin"
    source_path.write_bytes(content)
    blob_ids = EncryptionService().encrypt_file(
        source_path,
        vault_path,
        master_key.view(),
        b"vault-1",
        file_id,
    )
    return store.append_event(
        VaultEvent(
            event_id=event_id,
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(
                wall_time=wall_time,
                logical=0,
                device_id="device-a",
            ),
            payload={
                "node_id": node_id,
                "file_id": file_id,
                "parent_node_id": "folder-1",
                "name": name,
                "blob_ids": blob_ids,
                "content_hash": hashlib.sha256(content).hexdigest(),
                "mime_type": "application/octet-stream",
                "file_size_bytes": len(content),
                "encrypted_size_bytes": sum(
                    (vault_path / "blobs" / blob_id).stat().st_size for blob_id in blob_ids
                ),
                "metadata_json": None,
            },
            parents=parents or [],
        )
    )


def test_vault_integrity_service_passes_for_matching_db(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    create_vault_layout(vault_path)
    master_key = SecureMemory(b"k" * 32)
    store = _store(vault_path, master_key)
    folder = _append_folder_create(
        store,
        event_id="evt-folder",
        node_id="folder-1",
        name="docs",
        wall_time=1000,
    )
    _append_file_add(
        store,
        vault_path,
        master_key,
        tmp_path,
        event_id="evt-file",
        node_id="file-1",
        file_id="file-1",
        name="report.bin",
        content=b"hello integrity",
        wall_time=2000,
        parents=[folder.event_hash],
    )
    session_factory = _session_factory(tmp_path / "current.db")
    replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )

    report = VaultIntegrityService(
        _context(tmp_path, vault_path, session_factory, store, master_key)
    ).check()

    assert report.ok is True
    assert report.blocked_events == 0
    assert report.issues == []


def test_vault_integrity_service_reports_missing_blob_and_blocked_event(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "vault"
    create_vault_layout(vault_path)
    (vault_path / "blobs" / "placeholder.enc").write_bytes(b"x")
    master_key = SecureMemory(b"k" * 32)
    store = _store(vault_path, master_key)
    folder = _append_folder_create(
        store,
        event_id="evt-folder",
        node_id="folder-1",
        name="docs",
        wall_time=1000,
    )
    store.append_event(
        VaultEvent(
            event_id="evt-missing",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(
                wall_time=2000,
                logical=0,
                device_id="device-a",
            ),
            payload={
                "node_id": "file-1",
                "file_id": "file-1",
                "parent_node_id": "folder-1",
                "name": "missing.bin",
                "blob_ids": ["missing.enc"],
                "content_hash": hashlib.sha256(b"missing").hexdigest(),
                "mime_type": "application/octet-stream",
                "file_size_bytes": 7,
                "encrypted_size_bytes": 64,
                "metadata_json": None,
            },
            parents=[folder.event_hash],
        )
    )
    session_factory = _session_factory(tmp_path / "current.db")
    replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )

    report = VaultIntegrityService(
        _context(tmp_path, vault_path, session_factory, store, master_key)
    ).check()

    codes = {issue.code for issue in report.issues}
    assert report.ok is False
    assert report.blocked_events == 1
    assert "missing_blob" in codes
    assert "blocked_event" in codes


def test_vault_integrity_service_reports_db_mismatch(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    create_vault_layout(vault_path)
    master_key = SecureMemory(b"k" * 32)
    store = _store(vault_path, master_key)
    folder = _append_folder_create(
        store,
        event_id="evt-folder",
        node_id="folder-1",
        name="docs",
        wall_time=1000,
    )
    _append_file_add(
        store,
        vault_path,
        master_key,
        tmp_path,
        event_id="evt-file",
        node_id="file-1",
        file_id="file-1",
        name="report.bin",
        content=b"hello integrity",
        wall_time=2000,
        parents=[folder.event_hash],
    )
    session_factory = _session_factory(tmp_path / "current.db")
    replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )
    with session_scope(session_factory) as session:
        session.add(
            FileReference(
                node_id="rogue-node",
                parent_id=None,
                name="rogue",
                is_folder=True,
                virtual_path="/rogue",
                file_entry_id=None,
            )
        )

    report = VaultIntegrityService(
        _context(tmp_path, vault_path, session_factory, store, master_key)
    ).check()

    assert report.ok is False
    assert any(issue.code == "db_mismatch" for issue in report.issues)


def test_vault_integrity_service_reports_corrupt_event_object(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    create_vault_layout(vault_path)
    master_key = SecureMemory(b"k" * 32)
    store = _store(vault_path, master_key)
    event = _append_folder_create(
        store,
        event_id="evt-folder",
        node_id="folder-1",
        name="docs",
        wall_time=1000,
    )
    object_path = store.object_path(event.event_hash or "")
    payload = json.loads(object_path.read_text(encoding="utf-8"))
    payload["ciphertext"] = payload["ciphertext"][:-4] + "AAAA"
    object_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    session_factory = _session_factory(tmp_path / "current.db")
    report = VaultIntegrityService(
        _context(tmp_path, vault_path, session_factory, store, master_key)
    ).check()

    assert report.ok is False
    assert report.total_events == 1
    assert report.replayed_events == 0
    assert any(issue.code == "corrupt_event" for issue in report.issues)


def test_vault_integrity_service_passes_for_replayed_conflict_archives(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "vault"
    create_vault_layout(vault_path)
    master_key = SecureMemory(b"k" * 32)
    store = _store(vault_path, master_key)
    deleted_parent = _append_folder_create(
        store,
        event_id="evt-deleted-parent",
        node_id="folder-deleted",
        name="deleted",
        wall_time=1000,
    )
    folder = _append_folder_create(
        store,
        event_id="evt-folder",
        node_id="folder-1",
        name="docs",
        wall_time=1100,
    )
    store.append_event(
        VaultEvent(
            event_id="evt-delete-parent",
            type=EventType.FOLDER_DELETE,
            device_id="device-a",
            hlc=HybridLogicalClock(
                wall_time=1200,
                logical=0,
                device_id="device-a",
            ),
            payload={"node_id": "folder-deleted", "cascade": True},
            parents=[deleted_parent.event_hash],
        )
    )
    store.append_event(
        VaultEvent(
            event_id="evt-folder-conflict",
            type=EventType.FOLDER_MOVE,
            device_id="device-a",
            hlc=HybridLogicalClock(
                wall_time=1300,
                logical=0,
                device_id="device-a",
            ),
            payload={
                "node_id": "folder-1",
                "new_parent_node_id": "folder-deleted",
                "new_name": "docs",
            },
            parents=[folder.event_hash],
        )
    )
    session_factory = _session_factory(tmp_path / "current.db")
    replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
        app_data_dir=tmp_path / "app",
    )

    report = VaultIntegrityService(
        _context(tmp_path, vault_path, session_factory, store, master_key)
    ).check()

    assert report.ok is True
    assert report.issues == []


def test_vault_integrity_service_reports_sync_conflict_mismatch(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    create_vault_layout(vault_path)
    master_key = SecureMemory(b"k" * 32)
    store = _store(vault_path, master_key)
    folder = _append_folder_create(
        store,
        event_id="evt-folder",
        node_id="folder-1",
        name="docs",
        wall_time=1000,
    )
    _append_file_add(
        store,
        vault_path,
        master_key,
        tmp_path,
        event_id="evt-file",
        node_id="file-1",
        file_id="file-1",
        name="report.bin",
        content=b"hello integrity",
        wall_time=2000,
        parents=[folder.event_hash],
    )
    session_factory = _session_factory(tmp_path / "current.db")
    replay_vault_events(
        session_factory=session_factory,
        vault_path=vault_path,
        store=store,
    )
    with session_scope(session_factory) as session:
        session.add(
            SyncConflict(
                conflict_id="rogue-conflict",
                node_id="file-1",
                node_kind="file",
                archived_name="report.bin.conflict",
                archived_virtual_path="/.glyphweave_conflicts/report.bin.conflict",
                archived_file_ref_id=None,
                file_entry_id=None,
                reason_code="deleted_parent_move",
                reason_text="Injected mismatch",
                trigger_event_id="evt-rogue",
                trigger_event_hash="hash-rogue",
                trigger_event_type="file_move",
                origin_device_id="device-a",
                status="active",
            )
        )

    report = VaultIntegrityService(
        _context(tmp_path, vault_path, session_factory, store, master_key)
    ).check()

    assert report.ok is False
    assert any(issue.code == "db_mismatch" for issue in report.issues)
