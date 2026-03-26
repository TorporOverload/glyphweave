from __future__ import annotations

import heapq
import os
from dataclasses import dataclass, field
from pathlib import Path
from threading import Condition, Event as ThreadEvent, Thread
from time import monotonic
from typing import Any, Callable, cast

from sqlalchemy import select
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from app.infrastructure.persistence.db.model.processed_event import ProcessedEvent
from app.infrastructure.persistence.db.service.session import session_scope
from app.infrastructure.persistence.event_store import EventStore
from app.common.logging import logger

from app.core.domain.sync.models import DiscoveredEvent
from .replay import is_event_ready_for_replay, replay_vault_events

INITIAL_REPLAY_DELAY_SECONDS = 10.0
RETRY_DELAY_SECONDS = 5 * 60.0


@dataclass(order=True)
class _ScheduledReplay:
    run_at: float
    event_hash: str = field(compare=False)


class _EventObjectHandler(FileSystemEventHandler):
    def __init__(self, coordinator: "EventReplayRuntime") -> None:
        self._coordinator = coordinator

    def on_created(self, event: FileSystemEvent) -> None:
        self._schedule_if_event_object(event)

    def on_moved(self, event: FileSystemEvent) -> None:
        self._schedule_if_event_object(event)

    def _schedule_if_event_object(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        if not event.src_path:
            return

        raw_path = getattr(event, "dest_path", "") or event.src_path
        path = self._coerce_event_path(raw_path)
        if path is None:
            return
        if path.suffix != ".json":
            return
        self._coordinator.schedule(path.stem, INITIAL_REPLAY_DELAY_SECONDS)

    @staticmethod
    def _coerce_event_path(raw_path: object) -> Path | None:
        if isinstance(raw_path, bytes):
            return Path(os.fsdecode(raw_path))
        if isinstance(raw_path, str):
            return Path(raw_path)
        if not hasattr(raw_path, "__fspath__"):
            return None
        filesystem_path = cast(Any, raw_path).__fspath__()
        if isinstance(filesystem_path, bytes):
            return Path(os.fsdecode(filesystem_path))
        return Path(filesystem_path)


class EventReplayRuntime:
    def __init__(
        self,
        *,
        context: Any,
        store: EventStore,
        on_replayed: Callable[[Any], None],
    ) -> None:
        self._context = context
        self._on_replayed = on_replayed
        self._store = store
        self._condition = Condition()
        self._pending: dict[str, float] = {}
        self._queue: list[_ScheduledReplay] = []
        self._stop_event = ThreadEvent()
        self._thread: Any = None
        self._observer: Any = None

    def start(self) -> None:
        if self._thread is not None:
            return

        handler = _EventObjectHandler(self)
        observer = Observer()
        observer.schedule(handler, str(self._store.objects_dir), recursive=False)
        observer.start()

        thread = Thread(
            target=self.run,
            name="glyphweave-event-replay",
            daemon=True,
        )
        self._observer = observer
        self._thread = thread
        thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        observer = self._observer
        if observer is not None:
            observer.stop()
            observer.join(timeout=5)
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
        self._observer = None
        self._thread = None

    def schedule(self, event_hash: str, delay_seconds: float) -> None:
        run_at = monotonic() + delay_seconds
        with self._condition:
            current = self._pending.get(event_hash)
            if current is not None and current <= run_at:
                return
            self._pending[event_hash] = run_at
            heapq.heappush(self._queue, _ScheduledReplay(run_at, event_hash))
            self._condition.notify_all()

    def run(self) -> None:
        while True:
            scheduled = self._next_due()
            if scheduled is None:
                return
            self._process_event_hash(scheduled.event_hash)

    def _next_due(self) -> _ScheduledReplay | None:
        while True:
            if self._stop_event.is_set():
                return None
            with self._condition:
                while self._queue:
                    scheduled = self._queue[0]
                    current = self._pending.get(scheduled.event_hash)
                    if current != scheduled.run_at:
                        heapq.heappop(self._queue)
                        continue

                    wait_seconds = scheduled.run_at - monotonic()
                    if wait_seconds > 0:
                        self._condition.wait(timeout=wait_seconds)
                        break

                    heapq.heappop(self._queue)
                    self._pending.pop(scheduled.event_hash, None)
                    return scheduled
                else:
                    self._condition.wait(timeout=0.5)

    def _process_event_hash(self, event_hash: str) -> None:
        if self._is_already_processed(event_hash):
            return

        try:
            discovered = self._store.load_event(event_hash)
        except FileNotFoundError:
            return
        except Exception:
            logger.exception("Failed to load watched event %s", event_hash)
            self.schedule(event_hash, RETRY_DELAY_SECONDS)
            return

        wrapped = DiscoveredEvent(event=discovered, source_path=None)
        if not is_event_ready_for_replay(self._context.require_vault_path(), wrapped):
            self.schedule(event_hash, RETRY_DELAY_SECONDS)
            return

        try:
            result = replay_vault_events(
                session_factory=self._context.session_factory,
                vault_path=self._context.require_vault_path(),
                store=self._store,
                local_data_path=self._context.local_data_path,
            )
            if result.total > 0:
                self._on_replayed(self._context)
        except Exception:
            logger.exception("Failed to replay watched event %s", event_hash)
            self.schedule(event_hash, RETRY_DELAY_SECONDS)
            return

        if not self._is_already_processed(event_hash):
            self.schedule(event_hash, RETRY_DELAY_SECONDS)

    def _is_already_processed(self, event_hash: str) -> bool:
        session_factory = self._context.session_factory
        if session_factory is None:
            return True
        with session_scope(session_factory, commit=False) as session:
            processed = session.scalar(
                select(ProcessedEvent.id).where(ProcessedEvent.event_hash == event_hash)
            )
        return processed is not None
