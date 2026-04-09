from __future__ import annotations

import hashlib
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import joinedload, sessionmaker

from app.common.logging import logger
from app.common.paths.vault_layout import resolve_blob_path
from app.core.domain.sync.event_types import EventType
from app.core.domain.sync.models import (
    DiscoveredEvent,
    FileAddData,
    FileConflictArchiveData,
    FileUpdateData,
)
from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.file_entry import FileEntry
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.model.processed_event import ProcessedEvent
from app.infrastructure.persistence.db.model.sync_conflict import SyncConflict
from app.infrastructure.persistence.db.model.sync_node_state import SyncNodeState
from app.infrastructure.persistence.db.model.sync_tombstone import SyncTombstone
from app.infrastructure.persistence.db.service.session import session_scope
from app.services.models import VaultContext
from app.services.runtime.event_store_factory import build_event_store
from app.services.sync.replay import (
    _discovered_event_hash,
    _partition_replayable_events,
    replay_vault_events,
)


@dataclass(frozen=True)
class VaultIntegrityIssue:
    code: str
    message: str


@dataclass
class VaultIntegrityReport:
    total_events: int
    replayed_events: int
    blocked_events: int
    issues: list[VaultIntegrityIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.issues


class VaultIntegrityService:
    _CONFLICT_FOLDER_PATH = "/.glyphweave_conflicts"
    _CONFLICT_FOLDER_NODE_ID = "__glyphweave_conflict_folder__"

    def __init__(self, context: VaultContext) -> None:
        self._context = context

    def check(self) -> VaultIntegrityReport:
        session_factory = self._context.session_factory
        encryption_service = self._context.encryption_service
        master_key = self._context.master_key
        vault_id = self._context.vault_id
        if session_factory is None:
            raise RuntimeError("Database session is not initialized")
        if encryption_service is None:
            raise RuntimeError("Encryption service is not initialized")
        if master_key is None:
            raise RuntimeError("Master key is not initialized")
        if vault_id is None:
            raise RuntimeError("Vault ID is not initialized")

        vault_path = self._context.require_vault_path()
        store = self._context.event_store or build_event_store(self._context)
        discovered, issues = self._discover_events(store)
        ready, blocked = _partition_replayable_events(
            vault_path=vault_path,
            discovered=discovered,
            processed_hashes=set(),
        )
        issues.extend(
            self._verify_event_blobs(
                discovered=discovered,
                vault_path=vault_path,
            )
        )
        issues.extend(
            self._describe_blocked_events(
                blocked=blocked,
                ready=ready,
                vault_path=vault_path,
            )
        )

        replayed_events, rebuilt_snapshot = self._rebuild_snapshot(
            discovered=discovered,
            vault_path=vault_path,
            store=store,
        )
        current_snapshot = self._snapshot(session_factory)
        issues.extend(self._compare_snapshots(current_snapshot, rebuilt_snapshot))

        return VaultIntegrityReport(
            total_events=len(discovered)
            + sum(1 for issue in issues if issue.code == "corrupt_event"),
            replayed_events=replayed_events,
            blocked_events=len(blocked),
            issues=issues,
        )

    def _discover_events(
        self,
        store,
    ) -> tuple[list[DiscoveredEvent], list[VaultIntegrityIssue]]:
        discovered: list[DiscoveredEvent] = []
        issues: list[VaultIntegrityIssue] = []

        for path in sorted(store.objects_dir.glob("*.json")):
            event_hash = path.stem
            try:
                event = store.load_event(event_hash)
            except Exception as exc:
                issues.append(
                    VaultIntegrityIssue(
                        code="corrupt_event",
                        message=f"Event object {event_hash} could not be read: {exc}",
                    )
                )
                continue
            discovered.append(DiscoveredEvent(event=event, source_path=str(path)))

        return discovered, issues

    def _verify_event_blobs(
        self,
        *,
        discovered: list[DiscoveredEvent],
        vault_path: Path,
    ) -> list[VaultIntegrityIssue]:
        encryption_service = self._context.encryption_service
        master_key = self._context.require_master_key()
        vault_id = self._context.require_vault_id().encode("utf-8")
        if encryption_service is None:
            raise RuntimeError("Encryption service is not initialized")

        issues: list[VaultIntegrityIssue] = []
        seen_specs: set[tuple[str, tuple[str, ...], str]] = set()
        for item in discovered:
            spec = self._blob_spec_for_event(item)
            if spec is None:
                continue

            file_id, blob_ids, expected_hash, label = spec
            dedupe_key = (file_id, tuple(blob_ids), expected_hash)
            if dedupe_key in seen_specs:
                continue
            seen_specs.add(dedupe_key)

            missing = [
                blob_id
                for blob_id in blob_ids
                if not resolve_blob_path(vault_path, blob_id).exists()
            ]
            if missing:
                issues.append(
                    VaultIntegrityIssue(
                        code="missing_blob",
                        message=(
                            f"{label} references missing blob(s): "
                            f"{', '.join(sorted(missing))}"
                        ),
                    )
                )
                continue

            temp_dir = self._prepare_temp_dir("blob")
            try:
                output_path = temp_dir / "integrity-check.bin"
                try:
                    encryption_service.decrypt_file(
                        vault_path=vault_path,
                        blob_ids=blob_ids,
                        output_path=output_path,
                        master_key=master_key.view(),
                        vault_id=vault_id,
                        file_id=file_id,
                    )
                    actual_hash = hashlib.sha256(output_path.read_bytes()).hexdigest()
                except Exception as exc:
                    issues.append(
                        VaultIntegrityIssue(
                            code="corrupt_blob",
                            message=f"{label} failed decryption: {exc}",
                        )
                    )
                    continue
                finally:
                    try:
                        self._cleanup_temp_dir(temp_dir)
                    except Exception:
                        logger.warning(
                            "Failed to clean up temp dir during integrity check"
                        )
            except Exception as exc:
                issues.append(
                    VaultIntegrityIssue(
                        code="corrupt_blob",
                        message=f"{label} failed decryption: {exc}",
                    )
                )
                continue

            if actual_hash != expected_hash:
                issues.append(
                    VaultIntegrityIssue(
                        code="blob_hash_mismatch",
                        message=(
                            f"{label} content hash mismatch: "
                            f"expected {expected_hash}, got {actual_hash}"
                        ),
                    )
                )

        return issues

    def _describe_blocked_events(
        self,
        *,
        blocked: list[DiscoveredEvent],
        ready: list[DiscoveredEvent],
        vault_path: Path,
    ) -> list[VaultIntegrityIssue]:
        available_hashes = {_discovered_event_hash(item) for item in ready}
        issues: list[VaultIntegrityIssue] = []
        for item in blocked:
            event = item.event
            event_hash = _discovered_event_hash(item)
            missing_parents = [
                parent for parent in event.parents if parent not in available_hashes
            ]
            missing_blobs = self._missing_blobs_for_event(vault_path, item)
            reasons: list[str] = []
            if missing_parents:
                reasons.append(f"missing parents: {', '.join(missing_parents)}")
            if missing_blobs:
                reasons.append(f"missing blobs: {', '.join(missing_blobs)}")
            if not reasons:
                reasons.append("dependency chain could not be replayed")
            issues.append(
                VaultIntegrityIssue(
                    code="blocked_event",
                    message=(
                        f"Event {event_hash} ({event.type.value}) is blocked: "
                        f"{'; '.join(reasons)}"
                    ),
                )
            )
        return issues

    def _rebuild_snapshot(
        self,
        *,
        discovered: list[DiscoveredEvent],
        vault_path: Path,
        store,
    ) -> tuple[int, dict[str, set]]:
        temp_dir = self._prepare_temp_dir("rebuild")
        engine = None
        try:
            db_path = temp_dir / "integrity-rebuild.db"
            engine = create_engine(f"sqlite:///{db_path}")
            Base.metadata.create_all(engine)
            session_factory = sessionmaker(
                bind=engine, autoflush=False, autocommit=False
            )
            replay_store = _IntegrityReplayStore(discovered=discovered)
            result = replay_vault_events(
                session_factory=session_factory,
                vault_path=vault_path,
                store=replay_store,
                local_data_path=None,
                app_data_dir=None,
            )
            snapshot = self._snapshot(session_factory)
        finally:
            if engine is not None:
                engine.dispose()
            self._cleanup_temp_dir(temp_dir)
        return result.total, snapshot

    def _integrity_temp_root(self) -> Path:
        path = self._context.app_data_dir / ".integrity-tmp"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _prepare_temp_dir(self, prefix: str) -> Path:
        path = self._integrity_temp_root() / f"{prefix}-{uuid.uuid4().hex}"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _cleanup_temp_dir(path: Path) -> None:
        shutil.rmtree(path, ignore_errors=True)

    def _snapshot(self, session_factory: sessionmaker) -> dict[str, set]:
        with session_scope(session_factory, commit=False) as session:
            refs = (
                session.execute(
                    select(FileReference)
                    .options(
                        joinedload(FileReference.parent),
                        joinedload(FileReference.file_entry).joinedload(
                            FileEntry.blobs
                        ),
                    )
                    .order_by(FileReference.node_id)
                )
                .unique()
                .scalars()
                .all()
            )
            entries = (
                session.execute(
                    select(FileEntry)
                    .options(joinedload(FileEntry.blobs))
                    .order_by(FileEntry.file_id)
                )
                .unique()
                .scalars()
                .all()
            )
            processed = session.scalars(
                select(ProcessedEvent).order_by(ProcessedEvent.event_hash)
            ).all()
            conflicts = session.scalars(
                select(SyncConflict).order_by(SyncConflict.conflict_id)
            ).all()
            tombstones = session.scalars(
                select(SyncTombstone).order_by(SyncTombstone.node_id)
            ).all()
            node_states = session.scalars(
                select(SyncNodeState).order_by(SyncNodeState.node_id)
            ).all()

        return {
            "refs": {self._snapshot_ref(ref) for ref in refs},
            "entries": {
                (
                    entry.file_id,
                    entry.content_hash,
                    entry.mime_type,
                    entry.original_size_bytes,
                    entry.encrypted_size_bytes,
                    entry.metadata_json,
                    tuple(blob.blob_id for blob in entry.blobs),
                )
                for entry in entries
            },
            "processed": {
                (
                    row.event_hash,
                    row.event_id,
                    row.event_type,
                    row.device_id,
                    row.status,
                )
                for row in processed
            },
            "conflicts": {
                (
                    row.conflict_id,
                    row.node_id,
                    row.node_kind,
                    row.archived_name,
                    row.archived_virtual_path,
                    row.reason_code,
                    row.reason_text,
                    row.trigger_event_id,
                    row.trigger_event_hash,
                    row.trigger_event_type,
                    row.origin_device_id,
                    row.status,
                    row.resolution_event_id,
                )
                for row in conflicts
            },
            "tombstones": {
                (
                    row.node_id,
                    row.node_kind,
                    row.event_id,
                    row.device_id,
                    row.hlc_wall_time,
                    row.hlc_logical,
                    row.hlc_device_id,
                )
                for row in tombstones
            },
            "node_states": {
                (
                    row.node_id,
                    row.last_structural_hlc_wall_time,
                    row.last_structural_hlc_logical,
                    row.last_structural_hlc_device_id,
                    row.last_content_hlc_wall_time,
                    row.last_content_hlc_logical,
                    row.last_content_hlc_device_id,
                    row.last_event_id,
                )
                for row in node_states
            },
        }

    @classmethod
    def _snapshot_ref(
        cls, ref: FileReference
    ) -> tuple[str, str | None, str, bool, str, str | None]:
        node_id = str(ref.node_id)
        parent_node_id = str(ref.parent.node_id) if ref.parent is not None else None
        if ref.virtual_path == cls._CONFLICT_FOLDER_PATH:
            node_id = cls._CONFLICT_FOLDER_NODE_ID
        if (
            ref.parent is not None
            and ref.parent.virtual_path == cls._CONFLICT_FOLDER_PATH
        ):
            parent_node_id = cls._CONFLICT_FOLDER_NODE_ID
        return (
            node_id,
            parent_node_id,
            ref.name,
            ref.is_folder,
            ref.virtual_path,
            ref.file_entry.file_id if ref.file_entry is not None else None,
        )

    def _compare_snapshots(
        self,
        current: dict[str, set],
        rebuilt: dict[str, set],
    ) -> list[VaultIntegrityIssue]:
        issues: list[VaultIntegrityIssue] = []
        for key, current_values in current.items():
            rebuilt_values = rebuilt[key]
            if current_values == rebuilt_values:
                continue
            only_current = sorted(
                repr(item) for item in current_values - rebuilt_values
            )[:3]
            only_rebuilt = sorted(
                repr(item) for item in rebuilt_values - current_values
            )[:3]
            issues.append(
                VaultIntegrityIssue(
                    code="db_mismatch",
                    message=(
                        f"Current DB differs from replayed state for {key}: "
                        f"current_only={len(current_values - rebuilt_values)}, "
                        f"replayed_only={len(rebuilt_values - current_values)}, "
                        f"samples_current={only_current}, "
                        f"samples_replayed={only_rebuilt}"
                    ),
                )
            )
        return issues

    @staticmethod
    def _blob_spec_for_event(
        discovered: DiscoveredEvent,
    ) -> tuple[str, list[str], str, str] | None:
        event = discovered.event
        if event.type == EventType.FILE_ADD:
            payload = FileAddData.from_dict(event.payload)
            return (
                payload.file_id,
                payload.blob_ids,
                payload.content_hash,
                f"{payload.name} ({event.event_hash or event.event_id})",
            )
        if event.type == EventType.FILE_UPDATE:
            payload = FileUpdateData.from_dict(event.payload)
            return (
                payload.new_file_id,
                payload.new_blob_ids,
                payload.new_content_hash,
                f"update:{payload.node_id} ({event.event_hash or event.event_id})",
            )
        if event.type == EventType.FILE_CONFLICT_ARCHIVE:
            payload = FileConflictArchiveData.from_dict(event.payload)
            return (
                payload.file_id,
                payload.blob_ids,
                payload.content_hash,
                f"conflict:{payload.archived_name} ({
                    event.event_hash or event.event_id
                })",
            )
        return None

    @classmethod
    def _missing_blobs_for_event(
        cls,
        vault_path: Path,
        discovered: DiscoveredEvent,
    ) -> list[str]:
        spec = cls._blob_spec_for_event(discovered)
        if spec is None:
            return []
        _, blob_ids, _, _ = spec
        return [
            blob_id
            for blob_id in blob_ids
            if not resolve_blob_path(vault_path, blob_id).exists()
        ]


class _IntegrityReplayStore:
    def __init__(self, *, discovered: list[DiscoveredEvent]) -> None:
        self._discovered = list(discovered)
        self._event_hashes = {
            event_hash
            for item in self._discovered
            if (event_hash := _discovered_event_hash(item))
        }
        parent_hashes = {
            parent
            for item in self._discovered
            for parent in item.event.parents
            if parent
        }
        self._frontier_hashes = self._event_hashes - parent_hashes

    def discover_events(
        self,
        *,
        skip_hashes: set[str] | None = None,
    ) -> list[DiscoveredEvent]:
        if not skip_hashes:
            return list(self._discovered)
        return [
            item
            for item in self._discovered
            if _discovered_event_hash(item) not in skip_hashes
        ]

    def iter_frontier_hashes(self) -> set[str]:
        return set(self._frontier_hashes)

    def has_unprocessed_events(
        self,
        *,
        skip_hashes: set[str] | None = None,
    ) -> bool:
        if not skip_hashes:
            return bool(self._discovered)
        return any(
            _discovered_event_hash(item) not in skip_hashes for item in self._discovered
        )
