from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.infrastructure.persistence.db.base import DbBase
from app.services.models import VaultContext
from app.services.runtime.vault_runtime_bootstrap import (
    _index_replayed_entries,
    bootstrap_runtime_services,
)


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


def test_bootstrap_repairs_schema_when_required_objects_are_missing(
    tmp_path: Path, monkeypatch
) -> None:
    context = _build_context(tmp_path)
    db = DbBase(
        context.require_vault_id(),
        context.key_service.derive_database_key(),
        vaults_data_dir=context.app_data_dir / "vaults",
    )
    db.initialize_schema()
    with db.engine.begin() as conn:
        conn.exec_driver_sql("DROP TABLE sync_conflict")
    db.engine.dispose()

    _stub_bootstrap_dependencies(monkeypatch)
    init_calls: list[Path] = []
    original_initialize_schema = DbBase.initialize_schema

    def _tracked_initialize_schema(self) -> None:
        init_calls.append(self.db_path)
        original_initialize_schema(self)

    monkeypatch.setattr(DbBase, "initialize_schema", _tracked_initialize_schema)

    bootstrap_runtime_services(context)

    assert init_calls == [context.db.db_path]
    assert context.db.has_required_schema_objects() is True


def test_bootstrap_skips_schema_repair_when_required_objects_exist(
    tmp_path: Path, monkeypatch
) -> None:
    context = _build_context(tmp_path)
    db = DbBase(
        context.require_vault_id(),
        context.key_service.derive_database_key(),
        vaults_data_dir=context.app_data_dir / "vaults",
    )
    db.initialize_schema()
    db.engine.dispose()

    _stub_bootstrap_dependencies(monkeypatch)
    init_calls: list[Path] = []
    original_initialize_schema = DbBase.initialize_schema

    def _tracked_initialize_schema(self) -> None:
        init_calls.append(self.db_path)
        original_initialize_schema(self)

    monkeypatch.setattr(DbBase, "initialize_schema", _tracked_initialize_schema)

    bootstrap_runtime_services(context)

    assert init_calls == []
    assert context.db.has_required_schema_objects() is True


def _build_context(tmp_path: Path) -> VaultContext:
    app_data_dir = tmp_path / "app"
    vault_path = tmp_path / "vault"
    local_data_path = tmp_path / "local"
    app_data_dir.mkdir(parents=True, exist_ok=True)
    vault_path.mkdir(parents=True, exist_ok=True)
    local_data_path.mkdir(parents=True, exist_ok=True)

    class _FakeKeyService:
        @staticmethod
        def derive_database_key() -> str:
            return "ab" * 32

    return VaultContext(
        app_data_dir=app_data_dir,
        vault_id="vault-1",
        vault_name="Vault",
        vault_path=vault_path,
        local_data_path=local_data_path,
        key_service=_FakeKeyService(),
        master_key=SecureMemory(b"x" * 32),
    )


def _stub_bootstrap_dependencies(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.runtime.vault_runtime_bootstrap.restore_latest_db_dump",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "app.services.runtime.vault_runtime_bootstrap.build_event_store",
        lambda context: object(),
    )
    monkeypatch.setattr(
        "app.services.runtime.vault_runtime_bootstrap.replay_vault_events",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "app.services.runtime.vault_runtime_bootstrap.install_db_dump_hook",
        lambda **kwargs: SimpleNamespace(maybe_create_dump=lambda: None),
    )
    monkeypatch.setattr(
        "app.services.runtime.vault_runtime_bootstrap.FileService",
        lambda session_factory: object(),
    )
    monkeypatch.setattr(
        "app.services.runtime.vault_runtime_bootstrap.FolderService",
        lambda session_factory, vault_path: object(),
    )
    monkeypatch.setattr(
        "app.services.runtime.vault_runtime_bootstrap._index_replayed_entries",
        lambda context: None,
    )

    class _FakeReplayRuntime:
        def __init__(self, **kwargs) -> None:
            del kwargs

        def start(self) -> None:
            return None

    monkeypatch.setattr(
        "app.services.runtime.vault_runtime_bootstrap.EventReplayRuntime",
        _FakeReplayRuntime,
    )
    monkeypatch.setattr(
        "app.services.runtime.vault_runtime_bootstrap.FuseOrchestrator",
        lambda **kwargs: object(),
    )
