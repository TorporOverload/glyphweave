from app.core.crypto.primitives.aes_gcm import AESGCMCipher
from app.utils.logging import logger


def read_chunk(store, file_id: str, chunk_index: int):
    """Read and decrypt a single chunk from blob storage."""
    index = store._indices.get(file_id)
    if not index:
        return None

    entry = index.get(chunk_index)
    if not entry:
        return None

    blob_path, offset, enc_length = entry
    is_last = chunk_index == index.chunk_count - 1

    try:
        with open(blob_path, "rb") as f:
            f.seek(offset)
            encrypted_data = f.read(enc_length)

        if not encrypted_data:
            return None

        file_key = store._get_file_key(file_id)
        cipher = AESGCMCipher(file_key)
        plaintext = cipher.decrypt_chunk(
            encrypted_data,
            file_id,
            chunk_index,
            is_last,
        )
        return plaintext
    except Exception as e:
        logger.error(
            f"Failed to read chunk {chunk_index} from blob {blob_path.name}: {e}"
        )
        raise
