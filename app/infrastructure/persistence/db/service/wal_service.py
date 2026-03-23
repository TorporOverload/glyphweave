from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Set

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import sessionmaker

from app.common.logging import logger
from app.infrastructure.fuse.temp_store import TempStore
from app.infrastructure.persistence.db.model.WAL_entry import WalEntry
from app.infrastructure.persistence.db.service.session import session_scope


class WalService:
    def __init__(self, session_factory: sessionmaker, temp_store: TempStore):
        self._session_factory = session_factory
        self.temp_store = temp_store

    def log_write(
        self,
        file_ref_id: int,
        chunk_index: int,
        offset: int,
        length: int,
        data: bytes,
        file_id: str,
    ) -> WalEntry:
        temp_blob_id = self.temp_store.write_temp_blob(
            file_id=file_id,
            chunk_index=chunk_index,
            plaintext=data,
        )

        with session_scope(self._session_factory) as session:
            entry = WalEntry(
                file_reference_id=file_ref_id,
                operation="write",
                chunk_index=chunk_index,
                offset=offset,
                length=length,
                file_id=file_id,
                temp_blob_id=temp_blob_id,
                flushed=False,
            )
            session.add(entry)
            session.flush()

            logger.debug(
                "WAL: logged write for ref=%s, chunk=%s, blob=%s...",
                file_ref_id,
                chunk_index,
                temp_blob_id[:8],
            )
            return entry

    def log_truncate(self, file_ref_id: int, new_size: int, file_id: str) -> WalEntry:
        with session_scope(self._session_factory) as session:
            entry = WalEntry(
                file_reference_id=file_ref_id,
                operation="truncate",
                chunk_index=0,
                offset=0,
                length=new_size,
                file_id=file_id,
                temp_blob_id="",
                flushed=False,
            )
            session.add(entry)
            session.flush()

            logger.debug(
                f"WAL: logged truncate for ref={file_ref_id}, new_size={new_size}"
            )
            return entry

    def get_pending_entries(self, file_ref_id: int) -> List[WalEntry]:
        with session_scope(self._session_factory, commit=False) as session:
            return list(
                session.scalars(
                    select(WalEntry)
                    .where(
                        WalEntry.file_reference_id == file_ref_id,
                        WalEntry.flushed.is_(False),
                    )
                    .order_by(WalEntry.id)
                ).all()
            )

    def get_dirty_chunk_indices(self, file_ref_id: int) -> Set[int]:
        with session_scope(self._session_factory, commit=False) as session:
            rows = session.execute(
                select(WalEntry.chunk_index)
                .where(
                    WalEntry.file_reference_id == file_ref_id,
                    WalEntry.operation == "write",
                    WalEntry.flushed.is_(False),
                )
                .distinct()
            ).all()
            return {row[0] for row in rows}

    def mark_flushed(self, entry_ids: List[int]) -> None:
        if not entry_ids:
            return

        with session_scope(self._session_factory) as session:
            now = datetime.now(timezone.utc)
            session.execute(
                update(WalEntry)
                .where(WalEntry.id.in_(entry_ids))
                .values(flushed=True, flushed_at=now)
            )
            session.flush()
            logger.debug(f"WAL: marked {len(entry_ids)} entries as flushed")

    def checkpoint(self, file_ref_id: int) -> int:
        with session_scope(self._session_factory) as session:
            entries = session.scalars(
                select(WalEntry).where(
                    WalEntry.file_reference_id == file_ref_id,
                    WalEntry.flushed,
                )
            ).all()

            if not entries:
                return 0

            for entry in entries:
                if entry.temp_blob_id:
                    self.temp_store.delete_temp_blob(entry.temp_blob_id)

            entry_ids = [entry.id for entry in entries]
            session.execute(delete(WalEntry).where(WalEntry.id.in_(entry_ids)))
            session.flush()

            logger.debug(
                f"WAL: checkpointed {len(entries)} entries for ref={file_ref_id}"
            )
            return len(entries)

    def checkpoint_all_flushed(self) -> int:
        with session_scope(self._session_factory) as session:
            entries = session.scalars(
                select(WalEntry).where(WalEntry.flushed.is_(True))
            ).all()
            if not entries:
                return 0

            for entry in entries:
                if entry.temp_blob_id:
                    self.temp_store.delete_temp_blob(entry.temp_blob_id)

            entry_ids = [entry.id for entry in entries]
            session.execute(delete(WalEntry).where(WalEntry.id.in_(entry_ids)))
            session.flush()
            logger.info(f"WAL: checkpointed {len(entries)} entries globally")
            return len(entries)

    def get_unflushed_for_recovery(self) -> dict[int, list[WalEntry]]:
        with session_scope(self._session_factory, commit=False) as session:
            entries = session.scalars(
                select(WalEntry)
                .where(WalEntry.flushed.is_(False))
                .order_by(WalEntry.file_reference_id, WalEntry.id)
            ).all()

            result: dict[int, list[WalEntry]] = {}
            for entry in entries:
                result.setdefault(entry.file_reference_id, []).append(entry)
            return result

    def read_chunk_from_wal(self, entry: WalEntry) -> bytes | None:
        if not entry.temp_blob_id:
            return None
        return self.temp_store.read_temp_blob(
            file_id=entry.file_id,
            chunk_index=entry.chunk_index,
            blob_id=entry.temp_blob_id,
        )

    def get_latest_chunk_entries(self, file_ref_id: int) -> dict[int, WalEntry]:
        entries = self.get_pending_entries(file_ref_id)
        latest: dict[int, WalEntry] = {}
        for entry in entries:
            if entry.operation == "write":
                latest[entry.chunk_index] = entry
        return latest

    def cleanup_orphaned_blobs(self) -> int:
        with session_scope(self._session_factory, commit=False) as session:
            db_blob_ids = {
                row[0]
                for row in session.execute(
                    select(WalEntry.temp_blob_id)
                    .where(WalEntry.temp_blob_id != "")
                    .distinct()
                ).all()
            }
            return self.temp_store.cleanup_orphaned(db_blob_ids)

    def has_pending_writes(self, file_ref_id: int) -> bool:
        with session_scope(self._session_factory, commit=False) as session:
            count = session.scalar(
                select(func.count())
                .select_from(WalEntry)
                .where(
                    WalEntry.file_reference_id == file_ref_id,
                    WalEntry.flushed.is_(False),
                )
            )
            return bool(count and count > 0)

    def count_pending(self) -> int:
        with session_scope(self._session_factory, commit=False) as session:
            result = session.scalar(
                select(func.count())
                .select_from(WalEntry)
                .where(WalEntry.flushed.is_(False))
            )
            return int(result or 0)
