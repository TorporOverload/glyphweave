from __future__ import annotations

from pathlib import Path

from app.common import config


def test_get_app_data_dir_falls_back_to_default_when_env_not_set(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(config.APP_DATA_ENV_VAR, raising=False)

    result = config.get_app_data_dir()

    assert result == config.DEFAULT_APP_DATA_DIR


def test_get_debug_level_falls_back_to_default_for_empty_string(monkeypatch) -> None:
    monkeypatch.setenv(config.DEBUG_ENV_VAR, "")

    assert config.get_debug_level() == config.DEFAULT_DEBUG_LEVEL


def test_get_debug_level_falls_back_for_negative_value(monkeypatch) -> None:
    monkeypatch.setenv(config.DEBUG_ENV_VAR, "-5")

    assert config.get_debug_level() == config.DEFAULT_DEBUG_LEVEL


def test_get_debug_level_uses_zero_for_negative_result(monkeypatch) -> None:
    monkeypatch.setenv(config.DEBUG_ENV_VAR, "-1")

    result = config.get_debug_level()

    assert result == 0


def test_is_event_encryption_enabled_falls_back_for_unrecognized_value(
    monkeypatch,
) -> None:
    monkeypatch.setenv(config.EVENT_ENCRYPTION_ENV_VAR, "maybe")

    assert config.is_event_encryption_enabled() is True


def test_is_event_encryption_enabled_respects_case_insensitivity(monkeypatch) -> None:
    monkeypatch.setenv(config.EVENT_ENCRYPTION_ENV_VAR, "FALSE")

    assert config.is_event_encryption_enabled() is False


def test_is_event_encryption_enabled_accepts_various_true_values(
    monkeypatch, request
) -> None:
    true_values = {"1", "true", "yes", "on", "TRUE", "Yes", "ON"}

    for value in true_values:
        monkeypatch.setenv(config.EVENT_ENCRYPTION_ENV_VAR, value)
        assert config.is_event_encryption_enabled() is True, f"failed for {value}"


def test_is_event_encryption_enabled_accepts_various_false_values(
    monkeypatch, request
) -> None:
    false_values = {"0", "false", "no", "off", "FALSE", "No", "OFF"}

    for value in false_values:
        monkeypatch.setenv(config.EVENT_ENCRYPTION_ENV_VAR, value)
        assert config.is_event_encryption_enabled() is False, f"failed for {value}"


def test_get_log_file_path_creates_layout_when_not_configured(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(config.APP_DATA_ENV_VAR, str(tmp_path / "test-root"))
    monkeypatch.delenv(config.LOG_FILE_ENV_VAR, raising=False)

    result = config.get_log_file_path()

    assert result.parent.exists()
    assert result.name == "debug.log"


def test_get_error_log_file_path_creates_layout_when_not_configured(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(config.APP_DATA_ENV_VAR, str(tmp_path / "test-root"))
    monkeypatch.delenv(config.ERROR_LOG_FILE_ENV_VAR, raising=False)

    result = config.get_error_log_file_path()

    assert result.parent.exists()
    assert result.name == "error.log"


def test_get_vaults_data_dir_respects_environment_override(monkeypatch) -> None:
    custom_root = "/custom/vault/path"
    monkeypatch.setenv(config.APP_DATA_ENV_VAR, custom_root)

    result = config.get_vaults_data_dir()

    assert result == Path(custom_root) / config.VAULTS_DIR


def test_get_vaults_data_dir_is_app_data_dir_vaults_subdirectory(
    monkeypatch, tmp_path: Path
) -> None:
    app_data = tmp_path / ".test-app"
    monkeypatch.setenv(config.APP_DATA_ENV_VAR, str(app_data))

    result = config.get_vaults_data_dir()

    assert result == app_data / config.VAULTS_DIR


def test_env_var_whitespace_is_stripped(monkeypatch) -> None:
    monkeypatch.setenv(config.DEBUG_ENV_VAR, "  3  ")

    assert config.get_debug_level() == 3


def test_env_var_empty_after_stripping_falls_back_to_default(monkeypatch) -> None:
    monkeypatch.setenv(config.DEBUG_ENV_VAR, "   ")

    assert config.get_debug_level() == config.DEFAULT_DEBUG_LEVEL


def test_env_path_expands_user_tilde(monkeypatch) -> None:
    monkeypatch.setenv(config.APP_DATA_ENV_VAR, "~/my-glyphweave")

    result = config.get_app_data_dir()

    assert result == Path.home() / "my-glyphweave"
