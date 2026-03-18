from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import TYPE_CHECKING

from app.core.database.service.search import (
    get_pending_extractions,
    insert_document_content,
    update_extraction_status,
)
from app.core.database.service.session import session_scope
from app.core.runtime_layout import plaintext_staging_dir
from app.core.service.extraction_service import ExtractionService
from app.utils.logging import logger

if TYPE_CHECKING:
    from sqlalchemy.orm import sessionmaker

    from app.core.crypto.service.encryption_service import EncryptionService
    from app.core.database.model.file_entry import FileEntry


class IndexingService:
    def __init__(
        self,
        *,
        session_factory: "sessionmaker",
        encryption_service: "EncryptionService",
        vault_path: Path,
        cache_dir: Path,
        master_key: bytes | memoryview,
        vault_id: str,
    ) -> None:
        self._session_factory = session_factory
        self._encryption_service = encryption_service
        self._vault_path = Path(vault_path)
        self._cache_dir = Path(cache_dir)
        self._master_key = master_key
        self._vault_id = vault_id.encode("utf-8")

    def index_file_entry(self, entry: "FileEntry", filename: str) -> bool:
        """Decrypt, extract, and index a file entry into the FTS table."""
        if not ExtractionService.is_supported(filename):
            logger.info(f"Indexing skipped for unsupported format: {filename}")
            return False

        blob_ids = [blob.blob_id for blob in entry.blobs]
        if not blob_ids:
            logger.warning(f"Indexing skipped, no blobs available for entry {entry.id}")
            return False

        temp_path: Path | None = None
        try:
            logger.info(
                f"Indexing started: entry_id={entry.id}, file_id={entry.file_id}, "
                f"filename={filename}, blobs={len(blob_ids)}"
            )
            temp_path = self._decrypt_to_temp(entry.file_id, blob_ids, filename)
            logger.info(f"Indexing decrypt complete: entry_id={entry.id}, temp={temp_path}")
            result = ExtractionService.extract(temp_path)

            metadata_json = json.dumps(result.metadata) if result.metadata else None
            if result.error is not None:
                logger.warning(
                    f"Indexing extraction failed: entry_id={entry.id}, "
                    f"filename={filename}, error={result.error}"
                )
                self._set_status(
                    entry.id,
                    "failed",
                    preview="",
                    metadata_json=metadata_json,
                )
                return False

            if not result.content.strip():
                logger.info(
                    f"Indexing completed with empty text: entry_id={entry.id}, "
                    f"filename={filename}"
                )
                self._set_status(
                    entry.id,
                    "done",
                    preview=result.preview,
                    metadata_json=metadata_json,
                )
                return True

            with session_scope(self._session_factory) as session:
                logger.info(
                    f"Indexing writing FTS content: entry_id={entry.id}, "
                    f"filename={filename}, chars={len(result.content)}"
                )
                success = insert_document_content(session, str(entry.id), result.content)
                update_extraction_status(
                    session,
                    entry.id,
                    "done" if success else "failed",
                    preview=result.preview,
                    metadata_json=metadata_json,
                )
                if success:
                    logger.info(
                        f"Indexing completed successfully: entry_id={entry.id}, "
                        f"filename={filename}"
                    )
                else:
                    logger.warning(
                        f"Indexing failed during FTS insert: entry_id={entry.id}, "
                        f"filename={filename}"
                    )
                return success
        except Exception as exc:
            logger.exception(f"Indexing failed for {filename}: {exc}")
            try:
                self._set_status(entry.id, "failed", preview="")
            except Exception:
                logger.warning(
                    f"Failed to update extraction status after indexing error: {entry.id}"
                )
            return False
        finally:
            self._cleanup_temp_file(temp_path)

    def get_pending_entries(self, limit: int = 50) -> list["FileEntry"]:
        with session_scope(self._session_factory, commit=False) as session:
            return get_pending_extractions(session, limit=limit)

    def _decrypt_to_temp(self, file_id: str, blob_ids: list[str], filename: str) -> Path:
        temp_dir = plaintext_staging_dir(self._cache_dir)
        suffix = Path(filename).suffix
        temp_path = temp_dir / f"_extract_{file_id}_{secrets.token_hex(8)}{suffix}"
        logger.debug(
            f"Decrypting to staging file: file_id={file_id}, "
            f"filename={filename}, temp_path={temp_path}"
        )
        self._encryption_service.decrypt_file(
            vault_path=self._vault_path,
            blob_ids=blob_ids,
            output_path=temp_path,
            master_key=self._master_key,
            vault_id=self._vault_id,
            file_id=file_id,
        )
        return temp_path

    def _set_status(
        self,
        file_entry_id: int,
        status: str,
        *,
        preview: str | None = None,
        metadata_json: str | None = None,
    ) -> None:
        with session_scope(self._session_factory) as session:
            logger.debug(
                f"Updating extraction status: entry_id={file_entry_id}, "
                f"status={status}, preview_len={len(preview or '')}"
            )
            update_extraction_status(
                session,
                file_entry_id,
                status,
                preview=preview,
                metadata_json=metadata_json,
            )

    @staticmethod
    def _cleanup_temp_file(temp_path: Path | None) -> None:
        if temp_path is None or not temp_path.exists():
            return

        try:
            size = temp_path.stat().st_size
            with open(temp_path, "wb") as handle:
                if size:
                    handle.write(b"\x00" * size)
                handle.flush()
                os.fsync(handle.fileno())
            temp_path.unlink()
            logger.debug(f"Removed plaintext staging file: {temp_path}")
        except OSError as exc:
            logger.warning(f"Failed to clean plaintext temp file {temp_path}: {exc}")
