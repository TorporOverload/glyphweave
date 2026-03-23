import pytest

import app.infrastructure.platform.launcher as launcher_module
from app.infrastructure.platform.launcher import open_with_default_app


def test_open_with_default_app_uses_startfile_on_windows(tmp_path, monkeypatch) -> None:
    target = tmp_path / "report.txt"
    opened: list[str] = []

    monkeypatch.setattr(launcher_module.sys, "platform", "win32")
    monkeypatch.setattr(launcher_module.os, "startfile", opened.append)

    open_with_default_app(target)

    assert opened == [str(target)]


def test_open_with_default_app_rejects_non_windows_platforms(
    tmp_path, monkeypatch
) -> None:
    target = tmp_path / "report.txt"

    monkeypatch.setattr(launcher_module.sys, "platform", "darwin")

    with pytest.raises(OSError, match="Windows only"):
        open_with_default_app(target)
