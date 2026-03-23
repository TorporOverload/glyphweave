"""Public FUSE package exports.

See `docs/fuse.md` for the architecture overview and data-flow notes.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.infrastructure.fuse.chunk_store import ChunkIndex, ChunkStore
    from app.infrastructure.fuse.file_handle import FileHandle, FileHandleManager
    from app.infrastructure.fuse.meta_store import MetaStore
    from app.infrastructure.fuse.temp_store import TempStore
    from app.infrastructure.fuse.types import DirMeta, FileMeta

# Lazy imports avoid circular dependencies during package import.


def __getattr__(name: str):
    """Lazy import for modules with heavy dependencies to avoid circular imports."""
    if name == "Mounts":
        from app.infrastructure.fuse.fuse_orchestrator import FuseOrchestrator

        return FuseOrchestrator
    elif name == "SingleFileFS":
        from app.infrastructure.fuse.single_fs import SingleFileFS

        return SingleFileFS
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "SingleFileFS",
    "Mounts",
    "ChunkStore",
    "ChunkIndex",
    "TempStore",
    "MetaStore",
    "FileHandle",
    "FileHandleManager",
    "FileMeta",
    "DirMeta",
]

