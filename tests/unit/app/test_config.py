from __future__ import annotations

from pathlib import Path

from app.common import config


def test_get_app_data_dir_uses_environment_override(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(config.APP_DATA_ENV_VAR, str(tmp_path / "custom-root"))

    assert config.get_app_data_dir() == (tmp_path / "custom-root")


def test_get_vaults_data_dir_is_derived_from_app_data_dir(
    monkeypatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "custom-root"
    monkeypatch.setenv(config.APP_DATA_ENV_VAR, str(root))
    monkeypatch.setenv("GLYPHWEAVE_LOCAL_DIR", str(tmp_path / "ignored"))

    assert config.get_vaults_data_dir() == root / config.VAULTS_DIR


def test_event_encryption_is_enabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv(config.EVENT_ENCRYPTION_ENV_VAR, raising=False)

    assert config.is_event_encryption_enabled() is True


def test_event_encryption_can_be_disabled(monkeypatch) -> None:
    monkeypatch.setenv(config.EVENT_ENCRYPTION_ENV_VAR, "off")

    assert config.is_event_encryption_enabled() is False


def test_get_debug_level_falls_back_for_invalid_value(monkeypatch) -> None:
    monkeypatch.setenv(config.DEBUG_ENV_VAR, "not-a-number")

    assert config.get_debug_level() == config.DEFAULT_DEBUG_LEVEL
