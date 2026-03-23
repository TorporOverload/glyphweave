from __future__ import annotations

from enum import Enum


class EventType(str, Enum):
    FILE_ADD = "file_add"
    FILE_UPDATE = "file_update"
    FILE_MOVE = "file_move"
    FILE_DELETE = "file_delete"
    FOLDER_CREATE = "folder_create"
    FOLDER_MOVE = "folder_move"
    FOLDER_DELETE = "folder_delete"
    DB_DUMP_CREATED = "db_dump_created"
