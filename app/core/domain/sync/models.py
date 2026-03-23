from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.core.domain.sync.event_types import EventType


@dataclass(frozen=True)
class HybridLogicalClock:
    wall_time: int
    logical: int
    device_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "wall_time": self.wall_time,
            "logical": self.logical,
            "device_id": self.device_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HybridLogicalClock":
        return cls(
            wall_time=int(data["wall_time"]),
            logical=int(data["logical"]),
            device_id=str(data["device_id"]),
        )


@dataclass(frozen=True)
class VaultEvent:
    event_id: str
    type: EventType
    device_id: str
    hlc: HybridLogicalClock
    payload: dict[str, Any]
    parents: list[str] = field(default_factory=list)
    event_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "type": self.type.value,
            "device_id": self.device_id,
            "hlc": self.hlc.to_dict(),
            "payload": self.payload,
            "parents": list(self.parents),
            "event_hash": self.event_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VaultEvent":
        return cls(
            event_id=str(data["event_id"]),
            type=EventType(str(data["type"])),
            device_id=str(data["device_id"]),
            hlc=HybridLogicalClock.from_dict(data["hlc"]),
            payload=dict(data.get("payload", {})),
            parents=[str(parent) for parent in data.get("parents", [])],
            event_hash=(
                str(data["event_hash"]) if data.get("event_hash") is not None else None
            ),
        )


@dataclass(frozen=True)
class DiscoveredEvent:
    event: VaultEvent
    source_path: str | None = None


class ProcessingStatus(str, Enum):
    SUCCESS = "success"
    SKIPPED_DUPLICATE = "skipped_duplicate"
    SKIPPED_IDEMPOTENT = "skipped_idempotent"
    CONFLICT_RESOLVED = "conflict_resolved"
    CONFLICT_ARCHIVED = "conflict_archived"
    FAILED = "failed"


@dataclass
class ProcessingResult:
    event_id: str
    event_type: str
    status: ProcessingStatus
    message: str | None = None
    affected_ids: list[int] = field(default_factory=list)
    conflict_info: dict[str, Any] | None = None


@dataclass
class BatchProcessingResult:
    total: int
    successful: int
    skipped: int
    failed: int
    conflicts: int
    results: list[ProcessingResult] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total == 0:
            return 100.0
        return (self.successful / self.total) * 100


@dataclass(frozen=True)
class FileAddData:
    node_id: str
    file_id: str
    parent_node_id: str | None
    name: str
    blob_ids: list[str]
    content_hash: str
    mime_type: str
    file_size_bytes: int
    encrypted_size_bytes: int
    metadata_json: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileAddData":
        return cls(
            node_id=str(data["node_id"]),
            file_id=str(data["file_id"]),
            parent_node_id=(
                str(data["parent_node_id"])
                if data.get("parent_node_id") is not None
                else None
            ),
            name=str(data["name"]),
            blob_ids=[str(blob_id) for blob_id in data["blob_ids"]],
            content_hash=str(data["content_hash"]),
            mime_type=str(data["mime_type"]),
            file_size_bytes=int(data["file_size_bytes"]),
            encrypted_size_bytes=int(data["encrypted_size_bytes"]),
            metadata_json=(
                str(data["metadata_json"])
                if data.get("metadata_json") is not None
                else None
            ),
        )


@dataclass(frozen=True)
class FileDeleteData:
    node_id: str
    file_id: str | None = None
    reason: str = "user_action"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileDeleteData":
        return cls(
            node_id=str(data["node_id"]),
            file_id=str(data["file_id"]) if data.get("file_id") is not None else None,
            reason=str(data.get("reason", "user_action")),
        )


@dataclass(frozen=True)
class FileMoveData:
    node_id: str
    new_parent_node_id: str | None
    new_name: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileMoveData":
        return cls(
            node_id=str(data["node_id"]),
            new_parent_node_id=(
                str(data["new_parent_node_id"])
                if data.get("new_parent_node_id") is not None
                else None
            ),
            new_name=str(data["new_name"]),
        )


@dataclass(frozen=True)
class FileUpdateData:
    node_id: str
    old_file_id: str | None
    new_file_id: str
    old_blob_ids: list[str]
    new_blob_ids: list[str]
    old_content_hash: str | None
    new_content_hash: str
    new_file_size_bytes: int
    new_encrypted_size_bytes: int
    new_metadata_json: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileUpdateData":
        return cls(
            node_id=str(data["node_id"]),
            old_file_id=(
                str(data["old_file_id"])
                if data.get("old_file_id") is not None
                else None
            ),
            new_file_id=str(data["new_file_id"]),
            old_blob_ids=[str(blob_id) for blob_id in data.get("old_blob_ids", [])],
            new_blob_ids=[str(blob_id) for blob_id in data["new_blob_ids"]],
            old_content_hash=(
                str(data["old_content_hash"])
                if data.get("old_content_hash") is not None
                else None
            ),
            new_content_hash=str(data["new_content_hash"]),
            new_file_size_bytes=int(data["new_file_size_bytes"]),
            new_encrypted_size_bytes=int(data["new_encrypted_size_bytes"]),
            new_metadata_json=(
                str(data["new_metadata_json"])
                if data.get("new_metadata_json") is not None
                else None
            ),
        )


@dataclass(frozen=True)
class FolderCreateData:
    node_id: str
    parent_node_id: str | None
    name: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FolderCreateData":
        return cls(
            node_id=str(data["node_id"]),
            parent_node_id=(
                str(data["parent_node_id"])
                if data.get("parent_node_id") is not None
                else None
            ),
            name=str(data["name"]),
        )


@dataclass(frozen=True)
class FolderDeleteData:
    node_id: str
    cascade: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FolderDeleteData":
        return cls(
            node_id=str(data["node_id"]),
            cascade=bool(data.get("cascade", True)),
        )


@dataclass(frozen=True)
class FolderMoveData:
    node_id: str
    new_parent_node_id: str | None
    new_name: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FolderMoveData":
        return cls(
            node_id=str(data["node_id"]),
            new_parent_node_id=(
                str(data["new_parent_node_id"])
                if data.get("new_parent_node_id") is not None
                else None
            ),
            new_name=str(data["new_name"]),
        )


@dataclass(frozen=True)
class DBDumpCreatedData:
    device_id: str
    created_at: str
    db_size_bytes: int
    dump_name: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DBDumpCreatedData":
        return cls(
            device_id=str(data["device_id"]),
            created_at=str(data["created_at"]),
            db_size_bytes=int(data["db_size_bytes"]),
            dump_name=str(data["dump_name"]),
        )
