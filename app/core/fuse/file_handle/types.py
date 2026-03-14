from typing import Callable, Optional, Protocol

from app.core.fuse.types import FileMeta


class ChunkStoreProtocol(Protocol):
    def read_chunk(self, file_id: str, chunk_index: int) -> Optional[bytes]:
        """Read and return the plaintext bytes for a single chunk."""
        ...

    def write_chunk(self, file_id: str, chunk_index: int, data: bytes) -> None:
        """Persist plaintext bytes for a single chunk to the backing store."""
        ...

    def write_metadata(self, file_id: str, metadata: FileMeta) -> None:
        """Persist updated file metadata to the backing store."""
        ...

    def truncate_chunks(self, file_id: str, new_size: int) -> None:
        """Remove or trim chunks so the stored file does not exceed new_size bytes."""
        ...


OnChunkWriteCallback = Callable[[str, str, int, bytes], None]
