from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.services.models import VaultContext
from app.services.runtime.vault_runtime_bootstrap import _index_replayed_entries


@contextmanager
def _fake_session_scope(_session_factory, commit=False):
    del commit
    yield object()


def test_index_replayed_entries_indexes_supported_pending_files(
    tmp_path: Path, monkeypatch
) -> None:
    calls: list[tuple[int, str]] = []

    class _FakeIndexingService:
        def __init__(self, **kwargs) -> None:
            del kwargs

        def index_file_entry(self, entry, filename: str) -> bool:
            calls.append((entry.id, filename))
            return True

    entry = SimpleNamespace(
        id=11,
        references=[SimpleNamespace(name="report.txt"), SimpleNamespace(name="report.bin")],
    )
    context = VaultContext(
        app_data_dir=tmp_path,
        vault_id="vault-1",
        vault_path=tmp_path / "vault",
        local_data_path=tmp_path / "local",
        session_factory=object(),
        encryption_service=object(),
        master_key=SecureMemory(b"x" * 32),
    )

    monkeypatch.setattr(
        "app.services.runtime.vault_runtime_bootstrap.session_scope",
        _fake_session_scope,
    )
    monkeypatch.setattr(
        "app.services.runtime.vault_runtime_bootstrap.get_retriable_extractions",
        lambda session, limit=500: [entry],
    )
    monkeypatch.setattr(
        "app.services.runtime.vault_runtime_bootstrap.IndexingService",
        _FakeIndexingService,
    )

    _index_replayed_entries(context)

    assert calls == [(11, "report.txt")]
