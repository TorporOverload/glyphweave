from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.services.models import VaultContext
from app.services.runtime.vault_runtime_bootstrap import bootstrap_runtime_services


def _minimal_context(tmp_path: Path) -> VaultContext:
    return VaultContext(
        app_data_dir=tmp_path,
        vault_id="vault-1",
        vault_path=tmp_path / "vault",
        local_data_path=tmp_path / "local",
        master_key=SecureMemory(b"x" * 32),
    )


def _fake_key_service() -> MagicMock:
    svc = MagicMock()
    svc.derive_database_key.return_value = "dead" * 16
    return svc


@patch("app.services.runtime.vault_runtime_bootstrap.replay_vault_events")
@patch("app.services.runtime.vault_runtime_bootstrap._index_replayed_entries")
@patch("app.services.runtime.vault_runtime_bootstrap.install_db_dump_hook")
@patch("app.services.runtime.vault_runtime_bootstrap.build_event_store")
@patch("app.services.runtime.vault_runtime_bootstrap.FuseOrchestrator")
@patch("app.services.runtime.vault_runtime_bootstrap.EventReplayRuntime")
@patch("app.services.runtime.vault_runtime_bootstrap.restore_latest_db_dump")
@patch("app.services.runtime.vault_runtime_bootstrap.DbBase")
def test_bootstrap_repairs_missing_schema_objects(
    mock_db_base_cls: MagicMock,
    _mock_replay_runtime: MagicMock,
    _mock_fuse: MagicMock,
    _mock_build_store: MagicMock,
    _mock_install_dump: MagicMock,
    _mock_index: MagicMock,
    _mock_replay: MagicMock,
    _mock_restore: MagicMock,
    tmp_path: Path,
) -> None:
    mock_db_instance = MagicMock()
    mock_db_instance.get_missing_schema_objects.return_value = (
        {"file_entry", "search_index"},
        {"trigger_delete_search_index"},
    )
    mock_db_instance.SessionLocal = MagicMock()
    mock_db_instance.db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    mock_db_base_cls.return_value = mock_db_instance

    context = _minimal_context(tmp_path)
    context.key_service = _fake_key_service()
    vaults_data_dir = tmp_path / "vaults"
    context.app_data_dir = tmp_path

    bootstrap_runtime_services(context)

    mock_db_instance.initialize_schema.assert_called_once()
    missing_tables, missing_triggers = mock_db_instance.get_missing_schema_objects()
    assert missing_tables == {"file_entry", "search_index"}
    assert missing_triggers == {"trigger_delete_search_index"}


@patch("app.services.runtime.vault_runtime_bootstrap.replay_vault_events")
@patch("app.services.runtime.vault_runtime_bootstrap._index_replayed_entries")
@patch("app.services.runtime.vault_runtime_bootstrap.install_db_dump_hook")
@patch("app.services.runtime.vault_runtime_bootstrap.build_event_store")
@patch("app.services.runtime.vault_runtime_bootstrap.FuseOrchestrator")
@patch("app.services.runtime.vault_runtime_bootstrap.EventReplayRuntime")
@patch("app.services.runtime.vault_runtime_bootstrap.restore_latest_db_dump")
@patch("app.services.runtime.vault_runtime_bootstrap.DbBase")
def test_bootstrap_skips_repair_when_schema_complete(
    mock_db_base_cls: MagicMock,
    _mock_replay_runtime: MagicMock,
    _mock_fuse: MagicMock,
    _mock_build_store: MagicMock,
    _mock_install_dump: MagicMock,
    _mock_index: MagicMock,
    _mock_replay: MagicMock,
    _mock_restore: MagicMock,
    tmp_path: Path,
) -> None:
    mock_db_instance = MagicMock()
    mock_db_instance.get_missing_schema_objects.return_value = (set(), set())
    mock_db_instance.SessionLocal = MagicMock()
    mock_db_instance.db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    mock_db_base_cls.return_value = mock_db_instance

    context = _minimal_context(tmp_path)
    context.key_service = _fake_key_service()
    vaults_data_dir = tmp_path / "vaults"
    context.app_data_dir = tmp_path

    bootstrap_runtime_services(context)

    mock_db_instance.initialize_schema.assert_not_called()


@patch("app.services.runtime.vault_runtime_bootstrap.replay_vault_events")
@patch("app.services.runtime.vault_runtime_bootstrap._index_replayed_entries")
@patch("app.services.runtime.vault_runtime_bootstrap.install_db_dump_hook")
@patch("app.services.runtime.vault_runtime_bootstrap.build_event_store")
@patch("app.services.runtime.vault_runtime_bootstrap.FuseOrchestrator")
@patch("app.services.runtime.vault_runtime_bootstrap.EventReplayRuntime")
@patch("app.services.runtime.vault_runtime_bootstrap.restore_latest_db_dump")
@patch("app.services.runtime.vault_runtime_bootstrap.DbBase")
def test_bootstrap_with_missing_database_schema_objects(
    mock_db_base_cls: MagicMock,
    _mock_replay_runtime: MagicMock,
    _mock_fuse: MagicMock,
    _mock_build_store: MagicMock,
    _mock_install_dump: MagicMock,
    _mock_index: MagicMock,
    _mock_replay: MagicMock,
    _mock_restore: MagicMock,
    tmp_path: Path,
) -> None:
    mock_db_instance = MagicMock()
    missing_tables = {"file_blob_reference", "sync_tombstone"}
    missing_triggers = {"trigger_file_entry_content_changed"}
    mock_db_instance.get_missing_schema_objects.return_value = (
        missing_tables,
        missing_triggers,
    )
    mock_db_instance.SessionLocal = MagicMock()
    mock_db_instance.db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    mock_db_base_cls.return_value = mock_db_instance

    context = _minimal_context(tmp_path)
    context.key_service = _fake_key_service()
    context.app_data_dir = tmp_path

    bootstrap_runtime_services(context)

    mock_db_instance.initialize_schema.assert_called_once()


@patch("app.services.runtime.vault_runtime_bootstrap.replay_vault_events")
@patch("app.services.runtime.vault_runtime_bootstrap._index_replayed_entries")
@patch("app.services.runtime.vault_runtime_bootstrap.install_db_dump_hook")
@patch("app.services.runtime.vault_runtime_bootstrap.build_event_store")
@patch("app.services.runtime.vault_runtime_bootstrap.FuseOrchestrator")
@patch("app.services.runtime.vault_runtime_bootstrap.EventReplayRuntime")
@patch("app.services.runtime.vault_runtime_bootstrap.restore_latest_db_dump")
@patch("app.services.runtime.vault_runtime_bootstrap.DbBase")
def test_bootstrap_with_corrupted_search_index(
    mock_db_base_cls: MagicMock,
    _mock_replay_runtime: MagicMock,
    _mock_fuse: MagicMock,
    _mock_build_store: MagicMock,
    _mock_install_dump: MagicMock,
    _mock_index: MagicMock,
    _mock_replay: MagicMock,
    _mock_restore: MagicMock,
    tmp_path: Path,
) -> None:
    mock_db_instance = MagicMock()
    mock_db_instance.get_missing_schema_objects.return_value = (
        {"search_index", "search_filename_index"},
        set(),
    )
    mock_db_instance.SessionLocal = MagicMock()
    mock_db_instance.db_path = tmp_path / "vaults" / "vault-1" / "vault.db"
    mock_db_base_cls.return_value = mock_db_instance

    context = _minimal_context(tmp_path)
    context.key_service = _fake_key_service()
    context.app_data_dir = tmp_path

    bootstrap_runtime_services(context)

    mock_db_instance.initialize_schema.assert_called_once()