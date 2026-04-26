from unittest.mock import patch

import pytest

import app.common.logging as log_mod


class TestSanitizeDeviceId:
    def test_returns_unknown_for_none(self) -> None:
        from app.common.device_id import sanitize_device_id

        result = sanitize_device_id(None)
        assert result == "unknown-device"

    def test_returns_unknown_for_empty(self) -> None:
        from app.common.device_id import sanitize_device_id

        result = sanitize_device_id("")
        assert result == "unknown-device"

    def test_returns_unknown_for_whitespace(self) -> None:
        from app.common.device_id import sanitize_device_id

        result = sanitize_device_id("   ")
        assert result == "unknown-device"

    def test_normalizes_valid_id(self) -> None:
        from app.common.device_id import sanitize_device_id

        result = sanitize_device_id("My Device 123")
        assert result == "My-Device-123"

    def test_removes_special_characters(self) -> None:
        from app.common.device_id import sanitize_device_id

        result = sanitize_device_id("dev@#$%^&*()id")
        assert result == "dev-id"

    def test_strips_leading_trailing_hyphens(self) -> None:
        from app.common.device_id import sanitize_device_id

        result = sanitize_device_id("  ---device-id---  ")
        assert result == "device-id"


class TestEnsureDeviceId:
    def test_creates_new_device_id(self, tmp_path) -> None:
        from app.common.device_id import ensure_device_id

        device_id = ensure_device_id(tmp_path)
        assert device_id != "unknown-device"
        assert len(device_id) > 0

    def test_persists_device_id(self, tmp_path) -> None:
        from app.common.device_id import ensure_device_id, load_device_id

        device_id = ensure_device_id(tmp_path)
        loaded = load_device_id(tmp_path)
        assert device_id == loaded


class TestDeviceProfile:
    def test_load_device_profile_returns_dict(self, tmp_path) -> None:
        from app.common.device_id import ensure_device_id, load_device_profile

        ensure_device_id(tmp_path)
        profile = load_device_profile(tmp_path)

        assert isinstance(profile, dict)
        assert "device_id" in profile
        assert "alias" in profile
        assert "status" in profile

    def test_device_profile_status_defaults_to_active(self, tmp_path) -> None:
        from app.common.device_id import load_device_profile

        profile = load_device_profile(tmp_path)
        assert profile["status"] == "active"


class TestDeviceAlias:
    def test_set_and_resolve_alias(self, tmp_path) -> None:
        from app.common.device_id import (
            ensure_device_id,
            resolve_device_alias,
            set_device_alias,
        )

        device_id = ensure_device_id(tmp_path)
        set_device_alias(tmp_path, device_id, "My Device")

        alias = resolve_device_alias(tmp_path, device_id)
        assert alias == "My Device"

    def test_resolve_unknown_device_returns_none(self, tmp_path) -> None:
        from app.common.device_id import resolve_device_alias

        alias = resolve_device_alias(tmp_path, None)
        assert alias is None

    def test_set_alias_for_unknown_device_raises(self, tmp_path) -> None:
        from app.common.device_id import set_device_alias

        with pytest.raises(ValueError, match="Device ID is required"):
            set_device_alias(tmp_path, None, "alias")

    def test_alias_map_persists(self, tmp_path) -> None:
        from app.common.device_id import (
            ensure_device_id,
            load_device_profile,
            set_device_alias,
        )

        device_id = ensure_device_id(tmp_path)
        set_device_alias(tmp_path, "other-device", "Other Device")

        profile = load_device_profile(tmp_path)
        assert profile["global_aliases"].get("other-device") == "Other Device"


class TestDefaultFrontierAlias:
    def test_returns_empty_string_when_no_alias(self, tmp_path) -> None:
        from app.common.device_id import default_frontier_alias, ensure_device_id

        device_id = ensure_device_id(tmp_path)
        alias = default_frontier_alias(tmp_path, device_id)
        assert alias == ""
