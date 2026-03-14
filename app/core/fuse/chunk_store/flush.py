import hashlib
import math
import os
import secrets
from io import BytesIO
from typing import Dict

from app.core.runtime_layout import plaintext_staging_dir
from app.core.vault_layout import resolve_blob_path
from app.utils.logging import logger


def flush_to_blobs(
    store,
    file_id: str,
    file_ref_id: int,
    dirty_chunks: Dict[int, bytearray],
    original_size: int,
    mime_type: str = "application/octet-stream",
) -> None:
    """Persist dirty chunks by rebuilding encrypted blob snapshots."""
    if not dirty_chunks and original_size > 0:
        logger.debug("flush_to_blobs: no dirty chunks and file not empty, skipping")
        return

    full_content = assemble_full_content(
        store,
        file_id=file_id,
        dirty_chunks=dirty_chunks,
        total_size=original_size,
    )
    content_hash = hashlib.sha256(full_content).hexdigest()

    file_ref = store.folder_service.get_by_id(file_ref_id)
    if not file_ref:
        logger.error(f"FileReference {file_ref_id} not found during flush")
        return

    old_file_entry_id = file_ref.file_entry_id
    existing = store.file_service.find_by_content_hash(content_hash)

    new_entry_id = None
    if existing:
        logger.info(f"Dedup hit: reusing FileEntry {existing.id}")
        new_entry_id = existing.id
        if existing.id != old_file_entry_id:
            store.file_service.update_file_reference_entry(file_ref_id, existing.id)
    else:
        new_file_id = secrets.token_hex(16)
        new_entry = encrypt_and_store(
            store,
            plaintext=full_content,
            file_id=new_file_id,
            content_hash=content_hash,
            mime_type=mime_type,
        )
        new_entry_id = new_entry.id
        store.file_service.update_file_reference_entry(file_ref_id, new_entry.id)

    if old_file_entry_id and old_file_entry_id != new_entry_id:
        store.gc.cleanup_orphaned_entry(old_file_entry_id)

    store._indices.pop(file_id, None)
    logger.info(
        f"flush_to_blobs complete for file_ref {file_ref_id}: "
        f"{len(full_content)} bytes, hash={content_hash[:12]}..."
    )


def assemble_full_content(
    store,
    file_id: str,
    dirty_chunks: Dict[int, bytearray],
    total_size: int,
) -> bytes:
    """Build full plaintext from dirty cache + unchanged blob chunks."""
    if total_size == 0:
        return b""

    num_chunks = math.ceil(total_size / store.chunk_size)
    output = BytesIO()

    for chunk_idx in range(num_chunks):
        if chunk_idx in dirty_chunks:
            chunk_data = bytes(dirty_chunks[chunk_idx])
        else:
            chunk_data = store.read_chunk(file_id, chunk_idx)
            if chunk_data is None:
                remaining = min(
                    store.chunk_size, total_size - chunk_idx * store.chunk_size
                )
                chunk_data = b"\x00" * remaining
        output.write(chunk_data)

    return output.getvalue()[:total_size]


def encrypt_and_store(
    store,
    plaintext: bytes,
    file_id: str,
    content_hash: str,
    mime_type: str,
):
    """Encrypt plaintext into blob format and create DB entry records."""
    temp_dir = plaintext_staging_dir(store.cache_dir)
    temp_path = temp_dir / f"plain_{secrets.token_hex(8)}.tmp"

    try:
        with open(temp_path, "wb") as f:
            f.write(plaintext)
            f.flush()
            os.fsync(f.fileno())

        blob_ids = store.encryption_service.encrypt_file(
            file_path=temp_path,
            vault_path=store.vault_path,
            master_key=store.key_service.master_key.view(),
            vault_id=store.vault_id,
            file_id=file_id,
        )

        encrypted_size = sum(
            resolve_blob_path(store.vault_path, bid).stat().st_size for bid in blob_ids
        )
        return store.file_service.create_file_entry_with_blobs(
            file_id=file_id,
            content_hash=content_hash,
            mime_type=mime_type,
            encrypted_size=encrypted_size,
            original_size=len(plaintext),
            blob_ids=blob_ids,
        )
    finally:
        if temp_path.exists():
            size = temp_path.stat().st_size
            with open(temp_path, "wb") as f:
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
            temp_path.unlink()
