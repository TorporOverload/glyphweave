from types import SimpleNamespace

from app.core.domain.sync.models import BatchProcessingResult
from app.services.sync.runtime import EventReplayRuntime, RETRY_DELAY_SECONDS


def test_runtime_reschedules_when_replay_leaves_blocked_events(monkeypatch, tmp_path):
    captured_delay = None

    runtime = EventReplayRuntime(
        context=SimpleNamespace(
            session_factory=None,
            local_data_path=tmp_path / "local",
            app_data_dir=tmp_path / "app-data",
            require_vault_path=lambda: tmp_path / "vault",
        ),
        store=SimpleNamespace(objects_dir=tmp_path / "objects"),
        on_replayed=lambda _context: None,
    )

    def _capture_schedule(delay_seconds=None):
        nonlocal captured_delay
        captured_delay = delay_seconds

    monkeypatch.setattr(
        "app.services.sync.runtime.replay_vault_events",
        lambda **_kwargs: BatchProcessingResult(
            total=0,
            successful=0,
            skipped=0,
            failed=0,
            conflicts=0,
            blocked=1,
        ),
    )
    monkeypatch.setattr(runtime, "schedule_replay", _capture_schedule)

    runtime._process_event_hash("__replay__")

    assert captured_delay == RETRY_DELAY_SECONDS
