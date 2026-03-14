from pathlib import Path
from typing import List

from app.core.crypto.constants import (
    CHUNK_SIZE as BLOB_CHUNK_SIZE,
)
from app.core.crypto.constants import (
    CHUNKED_MAGIC,
    CHUNKED_VERSION,
    FILE_HEADER_SIZE_BYTES,
)
from app.core.crypto.primitives.aes_gcm import AESGCMCipher
from app.core.vault_layout import resolve_blob_path
from app.utils.logging import logger

from .types import ChunkIndex


def load_blob_index(store, file_id: str, blob_ids: List[str]) -> None:
    """Scan blob files and build chunk offset index for random access reads."""
    index = ChunkIndex()
    file_key = store._get_file_key(file_id)
    cipher = AESGCMCipher(file_key)

    chunk_index = 0
    for i, blob_id in enumerate(blob_ids):
        blob_path = resolve_blob_path(Path(store.vault_path), blob_id)
        if not blob_path.exists():
            logger.error(f"Blob not found: {blob_id}")
            continue

        blob_size = blob_path.stat().st_size
        offset = 0

        if i == 0:
            with open(blob_path, "rb") as f:
                encrypted_header = f.read(FILE_HEADER_SIZE_BYTES)

            plaintext_header = cipher.decrypt_header(encrypted_header, file_id)
            magic = plaintext_header[:4]
            if magic != CHUNKED_MAGIC:
                raise ValueError(f"Invalid magic in blob {blob_id}")

            version = plaintext_header[4]
            if version != CHUNKED_VERSION:
                raise ValueError(f"Unsupported version {version}")

            index.chunk_count = int.from_bytes(plaintext_header[5:9], "big")
            offset = FILE_HEADER_SIZE_BYTES

        while chunk_index < index.chunk_count and offset < blob_size:
            is_last = chunk_index == index.chunk_count - 1
            if is_last:
                enc_length = blob_size - offset
            else:
                enc_length = 12 + BLOB_CHUNK_SIZE + 16

            index.add(chunk_index, blob_path, offset, enc_length)
            offset += enc_length
            chunk_index += 1

    store._indices[file_id] = index
    logger.debug(
        f"Built blob index for {file_id}: "
        f"{index.chunk_count} chunks across {len(blob_ids)} blob(s)"
    )
