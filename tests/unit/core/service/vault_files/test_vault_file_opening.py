from types import SimpleNamespace

import pytest

import app.services.vault_files.vault_file_opening as opening_module
from app.services.models import OpenFileResult, PendingFallbackOpen, VaultContext
from app.services.vault_files.vault_file_opening import open_file_by_ref


class _FakeFileService:
    def __init__(self, file_ref) -> None:
        self.file_ref = file_ref
        self.calls: list[int] = []

    def get_file_reference_with_blobs(self, file_ref_id: int):
        self.calls.append(file_ref_id)
        return self.file_ref


def _result(source: str, message: str) -> OpenFileResult:
    return OpenFileResult(
        opened=True,
        source=source,
        file_ref_id=1,
        file_name="report.txt",
        file_path=None,
        message=message,
    )


def _file_ref(name: str = "report.txt", mime_type: str | None = "text/plain"):
    return SimpleNamespace(
        id=1,
        name=name,
        is_folder=False,
        file_entry=SimpleNamespace(mime_type=mime_type),
    )


def test_open_file_by_ref_raises_for_missing_reference(tmp_path) -> None:
    context = VaultContext(app_data_dir=tmp_path)
    file_service = _FakeFileService(None)

    with pytest.raises(FileNotFoundError, match="File reference not found: 7"):
        open_file_by_ref(
            context,
            fallback_opens={},
            file_service=file_service,
            encryption_service=SimpleNamespace(),
            file_ref_id=7,
            launch_in_default_app=True,
        )


def test_open_file_by_ref_prefers_existing_mount(tmp_path, monkeypatch) -> None:
    context = VaultContext(app_data_dir=tmp_path)
    file_service = _FakeFileService(_file_ref())
    events: list[str] = []

    monkeypatch.setattr(
        opening_module,
        "get_mounted_open_result",
        lambda *args, **kwargs: events.append("mounted") or _result("mount", "mounted"),
    )
    monkeypatch.setattr(
        opening_module,
        "get_cached_fallback_result",
        lambda *args, **kwargs: events.append("cached") or None,
    )

    result = open_file_by_ref(
        context,
        fallback_opens={},
        file_service=file_service,
        encryption_service=SimpleNamespace(),
        file_ref_id=1,
        launch_in_default_app=False,
    )

    assert result.message == "mounted"
    assert events == ["mounted"]


def test_open_file_by_ref_prefers_cached_fallback_after_mount_check(
    tmp_path,
    monkeypatch,
) -> None:
    context = VaultContext(app_data_dir=tmp_path)
    file_service = _FakeFileService(_file_ref())
    events: list[str] = []

    monkeypatch.setattr(
        opening_module,
        "get_mounted_open_result",
        lambda *args, **kwargs: events.append("mounted") or None,
    )
    monkeypatch.setattr(
        opening_module,
        "get_cached_fallback_result",
        lambda *args, **kwargs: events.append("cached")
        or _result("fallback", "cached"),
    )

    result = open_file_by_ref(
        context,
        fallback_opens={},
        file_service=file_service,
        encryption_service=SimpleNamespace(),
        file_ref_id=1,
        launch_in_default_app=False,
    )

    assert result.message == "cached"
    assert events == ["mounted", "cached"]


def test_open_file_by_ref_uses_mount_first_for_windows_office_files(
    tmp_path,
    monkeypatch,
) -> None:
    context = VaultContext(app_data_dir=tmp_path)
    file_service = _FakeFileService(
        _file_ref(
            name="report.docx",
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
    )
    events: list[str] = []

    monkeypatch.setattr(
        opening_module,
        "get_mounted_open_result",
        lambda *args, **kwargs: events.append("mounted-check") or None,
    )
    monkeypatch.setattr(
        opening_module,
        "get_cached_fallback_result",
        lambda *args, **kwargs: events.append("cached-check") or None,
    )
    monkeypatch.setattr(
        opening_module,
        "open_file_fallback",
        lambda *args, **kwargs: events.append("fallback-open")
        or _result("fallback", "fallback"),
    )
    monkeypatch.setattr(
        opening_module,
        "mount_file",
        lambda *args, **kwargs: events.append("mount-open")
        or _result("mount", "mount"),
    )

    result = open_file_by_ref(
        context,
        fallback_opens={},
        file_service=file_service,
        encryption_service=SimpleNamespace(),
        file_ref_id=1,
        launch_in_default_app=True,
    )

    assert result.message == "mount"
    assert events == ["mounted-check", "cached-check", "mount-open"]


def test_open_file_by_ref_tries_mount_then_fallback_for_non_office_files(
    tmp_path,
    monkeypatch,
) -> None:
    context = VaultContext(app_data_dir=tmp_path)
    file_service = _FakeFileService(
        _file_ref(name="report.txt", mime_type="text/plain")
    )
    events: list[str] = []

    monkeypatch.setattr(
        opening_module,
        "get_mounted_open_result",
        lambda *args, **kwargs: events.append("mounted-check") or None,
    )
    monkeypatch.setattr(
        opening_module,
        "get_cached_fallback_result",
        lambda *args, **kwargs: events.append("cached-check") or None,
    )
    monkeypatch.setattr(
        opening_module,
        "mount_file",
        lambda *args, **kwargs: events.append("mount-open") or None,
    )
    monkeypatch.setattr(
        opening_module,
        "open_file_fallback",
        lambda *args, **kwargs: events.append("fallback-open")
        or _result("fallback", "fallback"),
    )

    result = open_file_by_ref(
        context,
        fallback_opens={},
        file_service=file_service,
        encryption_service=SimpleNamespace(),
        file_ref_id=1,
        launch_in_default_app=True,
    )

    assert result.message == "fallback"
    assert events == ["mounted-check", "cached-check", "mount-open", "fallback-open"]
