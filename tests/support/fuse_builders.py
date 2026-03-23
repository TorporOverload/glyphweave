import hashlib
import secrets
from pathlib import Path
from typing import Any

from app.common.paths.vault_layout import resolve_blob_path
from app.infrastructure.fuse.single_fs import SingleFileFS
from app.infrastructure.persistence.db.model.file_reference import FileReference


def ordered_blob_ids(file_entry: Any) -> list[str]:
    """Return blob ids in their persisted chunk order."""
    return [
        blob.blob_id
        for blob in sorted(file_entry.blobs, key=lambda blob: blob.blob_index)
    ]


def create_encrypted_file_in_vault(
    *,
    temp_vault_path: Path,
    encryption_service: Any,
    file_service: Any,
    test_master_key: bytes,
    test_vault_id: bytes,
    source_file: Path,
    original_content: bytes,
    file_name: str,
    mime_type: str,
) -> tuple[FileReference, bytes]:
    """Encrypt a source file into the vault and register its DB records."""
    file_id = secrets.token_hex(16)

    blob_ids = encryption_service.encrypt_file(
        file_path=source_file,
        vault_path=temp_vault_path,
        master_key=test_master_key,
        vault_id=test_vault_id,
        file_id=file_id,
    )

    content_hash = hashlib.sha256(original_content).hexdigest()
    encrypted_size = sum(
        resolve_blob_path(temp_vault_path, blob_id).stat().st_size
        for blob_id in blob_ids
    )

    file_entry = file_service.create_file_entry_with_blobs(
        file_id=file_id,
        content_hash=content_hash,
        mime_type=mime_type,
        encrypted_size=encrypted_size,
        original_size=len(original_content),
        blob_ids=blob_ids,
    )
    file_ref = file_service.create_file_reference(
        name=file_name,
        parent_id=None,
        file_entry_id=file_entry.id,
    )

    return file_ref, original_content


def build_single_file_fs(
    *,
    file_ref: FileReference,
    temp_vault_path: Path,
    temp_runtime_cache_dir: Path,
    temp_mount_path: Path,
    key_service: Any,
    test_vault_id: bytes,
    test_master_key: bytes,
    session_factory: Any,
) -> SingleFileFS:
    """Create a SingleFileFS instance from an existing encrypted file reference."""
    file_entry = file_ref.file_entry

    return SingleFileFS(
        file_name=file_ref.name,
        file_id=file_entry.file_id,
        file_ref_id=file_ref.id,
        plaintext_size=file_entry.original_size_bytes,
        blob_ids=ordered_blob_ids(file_entry),
        vault_path=temp_vault_path,
        cache_dir=temp_runtime_cache_dir,
        mount_dir=temp_mount_path,
        key_service=key_service,
        vault_id=test_vault_id,
        session_factory=session_factory,
        master_key=test_master_key,
    )
