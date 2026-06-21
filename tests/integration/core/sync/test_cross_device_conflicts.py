from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import joinedload

from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import (
    HybridLogicalClock,
    ProcessingStatus,
    VaultEvent,
)
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.model.sync_conflict import SyncConflict
from app.infrastructure.persistence.db.model.sync_tombstone import SyncTombstone
from app.infrastructure.persistence.db.service.session import session_scope
from app.services.sync.folder_handlers import CONFLICT_FOLDER_NAME

from cross_device_helpers import make_device


def test_add_to_deleted_parent_archives_file(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    a = make_device("device-a", vault_path, tmp_path)
    b = make_device("device-b", vault_path, tmp_path)
    replay_dev = make_device("device-c", vault_path, tmp_path)

    # Device A: create folder at T=100
    a.store.append_event(
        VaultEvent(
            event_id="evt-folder-create",
            type=EventType.FOLDER_CREATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=100, logical=0, device_id="device-a"),
            payload={"node_id": "folder-1", "parent_node_id": None, "name": "shared"},
            parents=[],
        )
    )
    # Device A: delete folder at T=200
    a.store.append_event(
        VaultEvent(
            event_id="evt-folder-delete",
            type=EventType.FOLDER_DELETE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=200, logical=0, device_id="device-a"),
            payload={"node_id": "folder-1", "cascade": False},
            parents=[],
        )
    )
    # Device B: add file to the (now deleted) folder at T=300. 
    # The file is newer than delete
    b.store.append_event(
        VaultEvent(
            event_id="evt-file-add",
            type=EventType.FILE_ADD,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=300, logical=0, device_id="device-b"),
            payload={
                "node_id": "file-1",
                "file_id": "fid-1",
                "parent_node_id": "folder-1",
                "name": "orphan.txt",
                "blob_ids": [],
                "content_hash": "hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 21,
                "metadata_json": None,
            },
            parents=[],
        )
    )

    result = replay_dev.replay()

    file_add_result = next(
        r for r in result.results if r.event_id == "evt-file-add"
    )
    assert file_add_result.status == ProcessingStatus.CONFLICT_ARCHIVED

    with session_scope(replay_dev.session_factory) as session:
        archived = session.scalar(
            select(FileReference)
            .options(joinedload(FileReference.parent))
            .where(FileReference.node_id == "file-1")
        )
    assert archived is not None
    assert archived.parent is not None
    assert archived.parent.name == CONFLICT_FOLDER_NAME
    assert "orphan" in archived.name


def test_concurrent_file_update_higher_hlc_wins(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    a = make_device("device-a", vault_path, tmp_path)
    b = make_device("device-b", vault_path, tmp_path)
    replay_dev = make_device("device-c", vault_path, tmp_path)

    # Both devices see the original file_add (written by A)
    a.store.append_event(
        VaultEvent(
            event_id="evt-file-add",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=100, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-1",
                "file_id": "fid-original",
                "parent_node_id": None,
                "name": "shared.txt",
                "blob_ids": [],
                "content_hash": "hash-original",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 21,
                "metadata_json": None,
            },
            parents=[],
        )
    )
    # Device A updates at T=200 → hash-a
    a.store.append_event(
        VaultEvent(
            event_id="evt-update-a",
            type=EventType.FILE_UPDATE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=200, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-1",
                "new_file_id": "fid-a",
                "new_content_hash": "hash-a",
                "new_blob_ids": [],
                "new_encrypted_size_bytes": 21,
                "new_file_size_bytes": 5,
                "new_metadata_json": None,
            },
            parents=[],
        )
    )
    # Device B updates at T=300 → hash-b (higher HLC, wins)
    b.store.append_event(
        VaultEvent(
            event_id="evt-update-b",
            type=EventType.FILE_UPDATE,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=300, logical=0, device_id="device-b"),
            payload={
                "node_id": "file-1",
                "new_file_id": "fid-b",
                "new_content_hash": "hash-b",
                "new_blob_ids": [],
                "new_encrypted_size_bytes": 21,
                "new_file_size_bytes": 5,
                "new_metadata_json": None,
            },
            parents=[],
        )
    )

    replay_dev.replay()

    from app.infrastructure.persistence.db.model.file_entry import FileEntry

    with session_scope(replay_dev.session_factory) as session:
        ref = session.scalar(
            select(FileReference)
            .options(joinedload(FileReference.file_entry))
            .where(FileReference.node_id == "file-1")
        )
    assert ref is not None
    assert ref.file_entry is not None
    assert ref.file_entry.content_hash == "hash-b"


def test_delete_wins_over_older_update(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    a = make_device("device-a", vault_path, tmp_path)
    b = make_device("device-b", vault_path, tmp_path)
    replay_dev = make_device("device-c", vault_path, tmp_path)

    a.store.append_event(
        VaultEvent(
            event_id="evt-file-add",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=100, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-1",
                "file_id": "fid-1",
                "parent_node_id": None,
                "name": "doc.txt",
                "blob_ids": [],
                "content_hash": "hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 21,
                "metadata_json": None,
            },
            parents=[],
        )
    )
    # Device B updates at T=200
    b.store.append_event(
        VaultEvent(
            event_id="evt-update-b",
            type=EventType.FILE_UPDATE,
            device_id="device-b",
            hlc=HybridLogicalClock(wall_time=200, logical=0, device_id="device-b"),
            payload={
                "node_id": "file-1",
                "new_file_id": "fid-2",
                "new_content_hash": "hash-2",
                "new_blob_ids": [],
                "new_encrypted_size_bytes": 21,
                "new_file_size_bytes": 5,
                "new_metadata_json": None,
            },
            parents=[],
        )
    )
    # Device A deletes at T=300 (after the update)
    a.store.append_event(
        VaultEvent(
            event_id="evt-delete-a",
            type=EventType.FILE_DELETE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=300, logical=0, device_id="device-a"),
            payload={"node_id": "file-1"},
            parents=[],
        )
    )

    result = replay_dev.replay()

    with session_scope(replay_dev.session_factory) as session:
        ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
        tombstone = session.scalar(
            select(SyncTombstone).where(SyncTombstone.node_id == "file-1")
        )
    assert ref is None
    assert tombstone is not None

    # The update at T=200 processes before the delete at T=300 (HLC order),
    # so it succeeds. The delete then wins - file is removed with a tombstone.
    update_result = next(r for r in result.results if r.event_id == "evt-update-b")
    assert update_result.status == ProcessingStatus.SUCCESS


def test_conflict_resolved_event_propagates_to_second_device(tmp_path) -> None:
    vault_path = tmp_path / "vault"
    a = make_device("device-a", vault_path, tmp_path)
    b = make_device("device-b", vault_path, tmp_path)

    conflict_id = "conflict-uuid-1111"

    # Device A emits conflict archive (records that a file was archived)
    a.store.append_event(
        VaultEvent(
            event_id="evt-conflict-archive",
            type=EventType.FILE_CONFLICT_ARCHIVE,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=100, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-1",
                "file_id": "fid-1",
                "archived_name": "doc [conflict 2026-05-04].txt",
                "blob_ids": [],
                "content_hash": "hash-1",
                "mime_type": "text/plain",
                "file_size_bytes": 5,
                "encrypted_size_bytes": 21,
                "metadata_json": None,
                "conflict_id": conflict_id,
                "reason_code": "concurrent_update",
                "reason_text": "Two devices updated the same file concurrently",
                "trigger_event_id": "evt-other",
                "trigger_event_hash": None,
                "trigger_event_type": EventType.FILE_UPDATE.value,
                "trigger_device_id": "device-b",
                "origin_device_id": "device-b",
            },
            parents=[],
        )
    )

    # Device B replays - conflict is now active
    b.replay()

    with session_scope(b.session_factory) as session:
        conflict = session.scalar(
            select(SyncConflict).where(SyncConflict.conflict_id == conflict_id)
        )
    assert conflict is not None
    assert conflict.status == "active"

    # Device A emits resolution
    a.store.append_event(
        VaultEvent(
            event_id="evt-conflict-resolved",
            type=EventType.FILE_CONFLICT_RESOLVED,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=200, logical=0, device_id="device-a"),
            payload={
                "conflict_id": conflict_id,
                "node_id": "file-1",
                "resolution_status": "resolved",
                "resolution_reason": "explicit_action",
                "origin_device_id": "device-a",
            },
            parents=[],
        )
    )

    # Device B replays again - conflict should be resolved
    b.replay()

    with session_scope(b.session_factory) as session:
        conflict = session.scalar(
            select(SyncConflict).where(SyncConflict.conflict_id == conflict_id)
        )
    assert conflict is not None
    assert conflict.status == "resolved"


def test_blob_gated_event_unblocks_when_blob_appears(tmp_path) -> None:
    from app.common.paths.vault_layout import resolve_blob_path

    vault_path = tmp_path / "vault"
    a = make_device("device-a", vault_path, tmp_path)
    b = make_device("device-b", vault_path, tmp_path)

    missing_blob = "missing-blob-aabbcc.enc"
    blob_path = resolve_blob_path(vault_path, missing_blob)
    # Create the blob's parent directory so blob-gating is active.
    # When the parent dir exists, _all_blobs_exist() checks for each blob file.
    blob_path.parent.mkdir(parents=True, exist_ok=True)

    a.store.append_event(
        VaultEvent(
            event_id="evt-file-add",
            type=EventType.FILE_ADD,
            device_id="device-a",
            hlc=HybridLogicalClock(wall_time=100, logical=0, device_id="device-a"),
            payload={
                "node_id": "file-1",
                "file_id": "fid-1",
                "parent_node_id": None,
                "name": "big.bin",
                "blob_ids": [missing_blob],
                "content_hash": "hash-big",
                "mime_type": "application/octet-stream",
                "file_size_bytes": 1000,
                "encrypted_size_bytes": 1016,
                "metadata_json": None,
            },
            parents=[],
        )
    )

    # First replay - blob missing → event blocked, file not created
    result1 = b.replay()

    assert result1.blocked == 1
    with session_scope(b.session_factory) as session:
        ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
    assert ref is None

    # Blob arrives (simulating cloud sync delivering the encrypted blob)
    blob_path.write_bytes(b"\x00" * 1016)

    # Second replay - blob present → event processes
    result2 = b.replay()

    assert result2.successful == 1
    with session_scope(b.session_factory) as session:
        ref = session.scalar(
            select(FileReference).where(FileReference.node_id == "file-1")
        )
    assert ref is not None
    assert ref.name == "big.bin"
