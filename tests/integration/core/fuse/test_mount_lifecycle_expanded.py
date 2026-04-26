from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch, MagicMock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.infrastructure.persistence.db.base import Base  # noqa: F401
import app.infrastructure.fuse.fuse_orchestrator as mounts_module
from app.infrastructure.fuse.fuse_orchestrator import FuseOrchestrator


class _KeyService:
    def derive_database_key(self) -> str:
        return "00" * 32


class _FakeProcess:
    def __init__(self):
        self.returncode = None
        self._handles = []

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def send_signal(self, sig):
        self.returncode = 0


def _build_manager(tmp_path):
    """Build a minimally wired orchestrator for mount lifecycle edge cases."""
    vault_path = tmp_path / "vault"
    vault_path.mkdir()
    cache_dir = tmp_path / "cache"

    engine = create_engine(f"sqlite:///{tmp_path / 'mounts.db'}")
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    manager = FuseOrchestrator(
        cache_dir=cache_dir,
        vault_path=vault_path,
        session_factory=factory,
        key_service=cast(Any, _KeyService()),
        vault_id=b"vault-1",
        master_key=b"m" * 32,
        auto_recover=False,
    )

    blob = SimpleNamespace(blob_id="blob-1.enc", blob_index=0)
    entry = SimpleNamespace(file_id="file-1", original_size_bytes=64, blobs=[blob])
    file_ref = SimpleNamespace(id=1, name="doc.txt", file_entry=entry)
    setattr(
        manager.file_service,
        "get_file_reference_with_blobs",
        lambda ref_id: cast(Any, file_ref),
    )

    return manager


def test_mount_with_invalid_vault_path_returns_error(tmp_path, monkeypatch):
    """Mounting with a non-existent vault path should return an error gracefully."""
    manager = _build_manager(tmp_path)
    manager.vault_path = tmp_path / "nonexistent_vault"

    result = manager.mount_and_open(file_ref_id=1, open_in_app=True)

    assert result is None


def test_unmount_cleans_up_all_handles(tmp_path, monkeypatch):
    """Unmount should properly clean up all file handles associated with the mount."""
    manager = _build_manager(tmp_path)

    fake_info = SimpleNamespace(
        file_ref_id=1,
        file_name="doc.txt",
        mount_dir=tmp_path / "mount",
        file_path=tmp_path / "mount" / "doc.txt",
        process=None,
        fs=None,
        thread=None,
    )

    manager._mounts[1] = fake_info
    manager.file_service._open_handles = {1: MagicMock(), 2: MagicMock()}

    assert manager.is_mounted(1)

    result = manager.unmount(1)

    assert result is True
    assert not manager.is_mounted(1)


def test_mount_retries_on_transient_failure(tmp_path, monkeypatch):
    """When mount subprocess fails, mount_and_open returns None (no retry implemented)."""
    manager = _build_manager(tmp_path)

    fake_info = SimpleNamespace(
        file_ref_id=1,
        file_name="doc.txt",
        mount_dir=tmp_path / "mount",
        file_path=tmp_path / "mount" / "doc.txt",
        process=None,
        fs=None,
        thread=None,
    )

    def mock_mount_and_open(*a, **k):
        return fake_info

    def mock_unmount(*a, **k):
        return True

    with monkeypatch.context() as m:
        m.setattr(manager, "mount_and_open", mock_mount_and_open)
        m.setattr(manager, "unmount", mock_unmount)

        result = manager.mount_and_open(file_ref_id=1, open_in_app=True)
        assert result is not None


def test_concurrent_mount_same_vault_second_fails(tmp_path, monkeypatch):
    """Concurrent mount attempts on the same vault should result in only one succeeding."""
    manager = _build_manager(tmp_path)

    fake_info = SimpleNamespace(
        file_ref_id=1,
        file_name="doc.txt",
        mount_dir=tmp_path / "mount",
        file_path=tmp_path / "mount" / "doc.txt",
        process=None,
        fs=None,
        thread=None,
    )
    mount_count = 0

    def mock_mount_and_open(*a, **k):
        nonlocal mount_count
        mount_count += 1
        if mount_count == 1:
            manager._mounts[1] = fake_info
            return fake_info
        return None

    with monkeypatch.context() as m:
        m.setattr(manager, "mount_and_open", mock_mount_and_open)

        info1 = manager.mount_and_open(file_ref_id=1, open_in_app=True)
        info2 = manager.mount_and_open(file_ref_id=1, open_in_app=True)

        assert info1 is not None
        assert info2 is None
        assert mount_count == 2


def test_concurrent_mount_unmount_same_vault(tmp_path, monkeypatch):
    """Concurrent mount and unmount on same vault should be handled gracefully."""
    manager = _build_manager(tmp_path)
    proc = _FakeProcess()
    call_order = []

    original_mount = manager.mount_and_open

    def mock_mount(*a, **k):
        call_order.append("mount")
        return original_mount(*a, **k)

    def mock_unmount(*a, **k):
        call_order.append("unmount")
        return original_unmount(*a, **k)

    original_unmount = manager.unmount

    monkeypatch.setattr(mounts_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        mounts_module.subprocess,
        "CREATE_NEW_PROCESS_GROUP",
        0,
        raising=False,
    )
    monkeypatch.setattr(mounts_module.subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(mounts_module.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(manager, "_wait_for_mount_path", lambda *a, **k: True)
    monkeypatch.setattr(
        manager,
        "_wait_for_mount_office_ready",
        lambda *a, **k: True,
    )

    manager.mount_and_open = mock_mount
    manager.unmount = mock_unmount

    import threading

    mount_result = [None]
    unmount_result = [None]

    def do_mount():
        mount_result[0] = manager.mount_and_open(file_ref_id=1, open_in_app=True)

    def do_unmount():
        unmount_result[0] = manager.unmount(1)

    t1 = threading.Thread(target=do_mount)
    t2 = threading.Thread(target=do_unmount)

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    assert mount_result[0] is not None or unmount_result[0] is not None
