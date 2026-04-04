from __future__ import annotations

from enum import Enum


class EventType(str, Enum):
    FILE_ADD = "file_add"
    FILE_CONFLICT_ARCHIVE = "file_conflict_archive"
    FILE_CONFLICT_RESOLVED = "file_conflict_resolved"
    FILE_UPDATE = "file_update"
    FILE_MOVE = "file_move"
    FILE_DELETE = "file_delete"
    FOLDER_CREATE = "folder_create"
    FOLDER_CONFLICT_ARCHIVE = "folder_conflict_archive"
    FOLDER_CONFLICT_RESOLVED = "folder_conflict_resolved"
    FOLDER_MOVE = "folder_move"
    FOLDER_DELETE = "folder_delete"
    DB_DUMP_CREATED = "db_dump_created"
