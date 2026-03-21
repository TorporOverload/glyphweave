from pathlib import Path
from types import SimpleNamespace

import app.core.service.vault_file_mounts as mounts_module
from app.core.service.models import VaultContext
from app.core.service.vault_file_mounts import (
    get_mounted_open_result,
    list_mounted_unlocked_files,
    mount_file,
    reopen_mounted_file,
    unmount_mounted_file,
)


class _FakeMounts:
    def __init__(self, mounted_path: Path | None = None) -> None:
        self.mounted_path = mounted_path
        self.mounted = mounted_path is not None
        self.mount_and_open_calls: list[tuple[int, bool]] = []
        self.unmount_calls: list[tuple[int, bool]] = []
        self.active = {}

    def is_mounted(self, file_ref_id: int) -> bool:
        return self.mounted and file_ref_id == 1

    def get_mounted_path(self, file_ref_id: int):
        if file_ref_id == 1:
            return self.mounted_path
        return None

    def mount_and_open(self, file_ref_id: int, open_in_app: bool):
        self.mount_and_open_calls.append((file_ref_id, open_in_app))
        if not self.mounted_path:
            return None
        return SimpleNamespace(
            file_ref_id=file_ref_id,
            file_path=self.mounted_path,
            file_name="report.txt",
            mounted_at=123.0,
        )

    def get_active_mounts(self):
        return self.active

    def unmount(self, file_ref_id: int, background: bool = False) -> bool:
        self.unmount_calls.append((file_ref_id, background))
        return True


def test_get_mounted_open_result_reuses_existing_mount(tmp_path, monkeypatch) -> None:
    mounted_path = tmp_path / "report.txt"
    mounted_path.write_text("hello", encoding="utf-8")
    context = VaultContext(app_data_dir=tmp_path, mounts=_FakeMounts(mounted_path))
    opened_paths: list[Path] = []

    monkeypatch.setattr(mounts_module, "open_with_default_app", opened_paths.append)

    result = get_mounted_open_result(
        context,
        file_ref=SimpleNamespace(id=1, name="report.txt"),
        launch_in_default_app=True,
    )

    assert result is not None
    assert result.source == "mount"
    assert result.file_path == mounted_path
    assert result.message == "File is already mounted"
    assert opened_paths == [mounted_path]


def test_mount_file_wraps_mount_result(tmp_path) -> None:
    mounted_path = tmp_path / "mounted.txt"
    context = VaultContext(app_data_dir=tmp_path, mounts=_FakeMounts(mounted_path))

    result = mount_file(
        context,
        file_ref=SimpleNamespace(id=1, name="report.txt"),
        launch_in_default_app=False,
    )

    assert result is not None
    assert result.source == "mount"
    assert result.file_path == mounted_path
    assert context.mounts.mount_and_open_calls == [(1, False)]


def test_list_mounted_unlocked_files_maps_mount_info(tmp_path) -> None:
    mounted_path = tmp_path / "mounted.txt"
    mounts = _FakeMounts(mounted_path)
    mounts.active = {
        1: SimpleNamespace(
            file_ref_id=1,
            file_name="report.txt",
            file_path=mounted_path,
            mounted_at=12.0,
        )
    }
    context = VaultContext(app_data_dir=tmp_path, mounts=mounts)

    result = list_mounted_unlocked_files(context)

    assert len(result) == 1
    assert result[0].source == "mount"
    assert result[0].file_path == mounted_path


def test_reopen_mounted_file_opens_existing_path(tmp_path, monkeypatch) -> None:
    mounted_path = tmp_path / "mounted.txt"
    mounted_path.write_text("hello", encoding="utf-8")
    context = VaultContext(app_data_dir=tmp_path, mounts=_FakeMounts(mounted_path))
    opened_paths: list[Path] = []

    monkeypatch.setattr(mounts_module, "open_with_default_app", opened_paths.append)

    result = reopen_mounted_file(context, 1)

    assert result == "Opened mounted file"
    assert opened_paths == [mounted_path]


def test_unmount_mounted_file_uses_background_unmount(tmp_path) -> None:
    mounts = _FakeMounts(tmp_path / "mounted.txt")
    context = VaultContext(app_data_dir=tmp_path, mounts=mounts)

    result = unmount_mounted_file(context, 1)

    assert result == "Unmount started in background"
    assert mounts.unmount_calls == [(1, True)]
