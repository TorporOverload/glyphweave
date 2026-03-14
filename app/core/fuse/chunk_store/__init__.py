"""
ChunkStore public API.

This package keeps the historical import path
`from app.core.fuse.chunk_store import ChunkStore, ChunkIndex`
while splitting implementation into smaller modules.
"""

from pathlib import Path
from typing import Dict, List

from app.core.crypto.constants import FUSE_CHUNK_SIZE
from app.core.crypto.service.encryption_service import EncryptionService
from app.core.crypto.service.key_service import KeyService
from app.core.crypto.types import KeyPurpose
from app.core.database.service.file_service import FileService
from app.core.database.service.folder_service import FolderService
from app.core.database.service.gc_service import GarbageCollector
from app.core.fuse.types import FileMeta

from .flush import (
    assemble_full_content,
    encrypt_and_store,
    flush_to_blobs,
)
from .indexing import load_blob_index
from .io import read_chunk
from .types import ChunkIndex


class ChunkStore:
    """Blob-backed chunk store used by FUSE file systems."""

    def __init__(
        self,
        vault_path: Path,
        cache_dir: Path,
        key_service: KeyService,
        vault_id: bytes,
        file_service: FileService,
        folder_service: FolderService,
        gc: GarbageCollector,
        chunk_size: int = FUSE_CHUNK_SIZE,
    ):
        self.vault_path = vault_path
        self.cache_dir = Path(cache_dir)
        self.key_service = key_service
        self.vault_id = vault_id
        self.chunk_size = chunk_size
        self.encryption_service = EncryptionService()
        self.file_service = file_service
        self.folder_service = folder_service
        self.gc = gc

        self._indices: Dict[str, ChunkIndex] = {}
        self._key_cache: Dict[str, bytes] = {}

    def _get_file_key(self, file_id: str) -> bytes:
        if file_id not in self._key_cache:
            self._key_cache[file_id] = self.key_service.derive_sub_key(
                KeyPurpose.FILE,
                file_id,
            )
        return self._key_cache[file_id]

    def load_blob_index(self, file_id: str, blob_ids: List[str]) -> None:
        load_blob_index(self, file_id, blob_ids)

    def read_chunk(self, file_id: str, chunk_index: int):
        return read_chunk(self, file_id, chunk_index)

    def write_chunk(self, file_id: str, chunk_index: int, data: bytes) -> None:
        del file_id, chunk_index, data

    def write_metadata(self, file_id: str, metadata: FileMeta) -> None:
        del file_id, metadata

    def truncate_chunks(self, file_id: str, new_size: int) -> None:
        del file_id, new_size

    def flush_to_blobs(
        self,
        file_id: str,
        file_ref_id: int,
        dirty_chunks: Dict[int, bytearray],
        original_size: int,
        mime_type: str = "application/octet-stream",
    ) -> None:
        flush_to_blobs(
            self,
            file_id=file_id,
            file_ref_id=file_ref_id,
            dirty_chunks=dirty_chunks,
            original_size=original_size,
            mime_type=mime_type,
        )

    def _assemble_full_content(
        self,
        file_id: str,
        dirty_chunks: Dict[int, bytearray],
        total_size: int,
    ) -> bytes:
        return assemble_full_content(
            self,
            file_id=file_id,
            dirty_chunks=dirty_chunks,
            total_size=total_size,
        )

    def _encrypt_and_store(
        self,
        plaintext: bytes,
        file_id: str,
        content_hash: str,
        mime_type: str,
    ):
        return encrypt_and_store(
            self,
            plaintext=plaintext,
            file_id=file_id,
            content_hash=content_hash,
            mime_type=mime_type,
        )


__all__ = ["ChunkIndex", "ChunkStore"]
