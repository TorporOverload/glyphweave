from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import joinedload
from sqlalchemy.orm.exc import DetachedInstanceError

from app.infrastructure.persistence.db.model.extraction_status import ExtractionStatus
from app.infrastructure.persistence.db.service.search import (
    get_pending_extractions,
    insert_document_content,
    update_extraction_status,
)
from app.infrastructure.persistence.db.service.session import session_scope
from app.common.paths.runtime_layout import plaintext_staging_dir
from app.services.content.extraction_service import ExtractionService
from app.services.content.metadata_service import FileMetadataService
from app.common.logging import logger

if TYPE_CHECKING:
    from sqlalchemy.orm import sessionmaker

    from app.infrastructure.crypto.service.encryption_service import EncryptionService
    from app.infrastructure.persistence.db.model.file_entry import FileEntry


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
        file_id, blob_ids = self._resolve_entry_payload(entry)
        if not blob_ids:
            logger.warning(f"Indexing skipped, no blobs available for entry {entry.id}")
            return False

        temp_path: Path | None = None
        try:
            logger.info(
                f"Indexing started: entry_id={entry.id}, file_id={file_id}, "
                f"filename={filename}, blobs={len(blob_ids)}"
            )
            temp_path = self._decrypt_to_temp(file_id, blob_ids, filename)
            logger.info(
                f"Indexing decrypt complete: entry_id={entry.id}, temp={temp_path}"
            )
            metadata = self._extract_metadata(temp_path)
            if not ExtractionService.is_supported(filename):
                logger.info(f"Indexing skipped for unsupported format: {filename}")
                self._set_status(
                    entry.id,
                    ExtractionStatus.UNSUPPORTED,
                    preview="",
                    metadata_json=json.dumps(metadata) if metadata else None,
                )
                return False
            result = ExtractionService.extract(temp_path)
            return self._store_extraction_result(entry.id, filename, result, metadata)
        except Exception as exc:
            logger.exception(f"Indexing failed for {filename}: {exc}")
            try:
                self._set_status(entry.id, ExtractionStatus.FAILED, preview="")
            except Exception:
                logger.warning(
                    "Failed to update extraction status after indexing error: "
                    + str(entry.id)
                )
            return False
        finally:
            self._cleanup_temp_file(temp_path)

    def index_source_file(
        self,
        file_entry_id: int,
        source_path: Path,
        filename: str,
    ) -> bool:
        """Index a newly imported plaintext source file directly."""
        path = Path(source_path)
        try:
            logger.info(
                f"Indexing started from source file: entry_id={file_entry_id}, "
                f"filename={filename}, source={path}"
            )
            metadata = self._extract_metadata(path)
            if not ExtractionService.is_supported(filename):
                logger.info(f"Indexing skipped for unsupported format: {filename}")
                self._set_status(
                    file_entry_id,
                    ExtractionStatus.UNSUPPORTED,
                    preview="",
                    metadata_json=json.dumps(metadata) if metadata else None,
                )
                return False
            result = ExtractionService.extract(path)
            return self._store_extraction_result(
                file_entry_id,
                filename,
                result,
                metadata,
            )
        except Exception as exc:
            logger.exception(f"Indexing failed for {filename} from source file: {exc}")
            try:
                self._set_status(file_entry_id, ExtractionStatus.FAILED, preview="")
            except Exception:
                logger.warning(
                    "Failed to update extraction status after indexing error: "
                    f"{file_entry_id}"
                )
            return False

    def get_pending_entries(self, limit: int = 50) -> list["FileEntry"]:
        with session_scope(self._session_factory, commit=False) as session:
            return get_pending_extractions(session, limit=limit)

    def _store_extraction_result(
        self,
        file_entry_id: int,
        filename: str,
        result,
        base_metadata: dict | None = None,
    ) -> bool:
        merged_metadata = dict(base_metadata or {})
        merged_metadata.update(result.metadata or {})
        metadata_json = json.dumps(merged_metadata) if merged_metadata else None
        if result.error is not None:
            logger.warning(
                f"Indexing extraction failed: entry_id={file_entry_id}, "
                f"filename={filename}, error={result.error}"
            )
            self._set_status(
                file_entry_id,
                ExtractionStatus.FAILED,
                preview="",
                metadata_json=metadata_json,
            )
            return False

        if not result.content.strip():
            logger.info(
                f"Indexing completed with empty text: entry_id={file_entry_id}, "
                f"filename={filename}"
            )
            self._set_status(
                file_entry_id,
                ExtractionStatus.DONE,
                preview=result.preview,
                metadata_json=metadata_json,
            )
            return True

        logger.info(
            f"Indexing writing FTS content: entry_id={file_entry_id}, "
            f"filename={filename}, chars={len(result.content)}"
        )
        with session_scope(self._session_factory) as session:
            success = insert_document_content(session, file_entry_id, result.content)
            update_extraction_status(
                session,
                file_entry_id,
                ExtractionStatus.DONE if success else ExtractionStatus.FAILED,
                preview=result.preview,
                metadata_json=metadata_json,
            )
        if success:
            logger.info(
                f"Indexing completed successfully: entry_id={file_entry_id}, "
                f"filename={filename}"
            )
        else:
            logger.warning(
                f"Indexing failed during FTS insert: entry_id={file_entry_id}, "
                f"filename={filename}"
            )
        return success

    @staticmethod
    def _extract_metadata(file_path: Path) -> dict[str, object]:
        metadata_result = FileMetadataService.extract(file_path)
        if metadata_result.error is not None:
            logger.warning(
                f"Metadata extraction failed for {file_path}: {metadata_result.error}"
            )
            return {}
        return metadata_result.metadata

    def _resolve_entry_payload(self, entry: "FileEntry") -> tuple[str, list[str]]:
        try:
            blob_ids = [blob.blob_id for blob in entry.blobs]
            file_id = entry.file_id
            return file_id, blob_ids
        except DetachedInstanceError:
            logger.debug(
                f"Reloading detached FileEntry for indexing: entry_id={entry.id}"
            )

        from app.infrastructure.persistence.db.model.file_entry import FileEntry

        with session_scope(self._session_factory, commit=False) as session:
            loaded_entry = session.scalars(
                select(FileEntry)
                .options(joinedload(FileEntry.blobs))
                .where(FileEntry.id == entry.id)
            ).first()

            if loaded_entry is None:
                raise FileNotFoundError(
                    f"FileEntry {entry.id} not found while preparing indexing payload"
                )

            return loaded_entry.file_id, [blob.blob_id for blob in loaded_entry.blobs]

    def _decrypt_to_temp(
        self, file_id: str, blob_ids: list[str], filename: str
    ) -> Path:
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
        status: ExtractionStatus,
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

