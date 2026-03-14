from pathlib import Path
from typing import Dict, Optional


class ChunkIndex:
    """Maps chunk index -> (blob_path, offset, encrypted_length)."""

    def __init__(self):
        self.entries: Dict[int, tuple[Path, int, int]] = {}
        self.chunk_count: int = 0

    def add(self, chunk_index: int, blob_path: Path, offset: int, enc_length: int):
        """Register a chunk's blob location, byte offset, and encrypted length."""
        self.entries[chunk_index] = (blob_path, offset, enc_length)

    def get(self, chunk_index: int) -> Optional[tuple[Path, int, int]]:
        """Return the (blob_path, offset, enc_length) tuple for a chunk index."""
        return self.entries.get(chunk_index)
