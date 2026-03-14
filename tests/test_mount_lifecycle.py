from types import SimpleNamespace
from typing import Any, cast

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database.base import Base  # noqa: F401
import app.core.fuse.fuse_orchestrator as mounts_module
from app.core.fuse.fuse_orchestrator import FuseOrchestrator


class _KeyService:
    def derive_database_key(self) -> str:
        return "00" * 32


class _FakeProcess:
    def __init__(self):
        self.returncode = None

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
    vault_path = tmp_path / "vault"
    vault_path.mkdir()
    cache_dir = tmp_path / "cache"

    engine = create_engine(f"sqlite:///{tmp_path / 'mounts.db'}")
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False)()

    manager = FuseOrchestrator(
        cache_dir=cache_dir,
        vault_path=vault_path,
        db_session=session,
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


def test_mount_path_timeout_cleans_up_state(tmp_path, monkeypatch):
    manager = _build_manager(tmp_path)
    proc = _FakeProcess()

    monkeypatch.setattr(mounts_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        mounts_module.subprocess,
        "CREATE_NEW_PROCESS_GROUP",
        0,
        raising=False,
    )
    monkeypatch.setattr(mounts_module.subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(mounts_module.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(manager, "_wait_for_mount_path", lambda *a, **k: False)

    result = manager.mount_and_open(file_ref_id=1, open_in_app=True)

    assert result is None
    assert not manager.is_mounted(1)
    assert proc.poll() == 0


def test_mount_responsiveness_timeout_cleans_up_state(tmp_path, monkeypatch):
    manager = _build_manager(tmp_path)
    proc = _FakeProcess()

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
        lambda *a, **k: False,
    )

    result = manager.mount_and_open(file_ref_id=1, open_in_app=True)

    assert result is None
    assert not manager.is_mounted(1)
    assert proc.poll() == 0


def test_windows_mount_process_uses_devnull_pipes(tmp_path, monkeypatch):
    manager = _build_manager(tmp_path)
    proc = _FakeProcess()

    captured = {}

    def _fake_popen(*args, **kwargs):
        captured.update(kwargs)
        return proc

    monkeypatch.setattr(mounts_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        mounts_module.subprocess,
        "CREATE_NEW_PROCESS_GROUP",
        0,
        raising=False,
    )
    monkeypatch.setattr(mounts_module.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(mounts_module.subprocess, "run", lambda *a, **k: None)

    info = manager.mount_and_open(file_ref_id=1, open_in_app=False)

    assert info is not None
    assert captured["stdout"] is mounts_module.subprocess.DEVNULL
    assert captured["stderr"] is mounts_module.subprocess.DEVNULL
    assert manager.is_mounted(1)

    assert manager.unmount(1) is True
    assert not manager.is_mounted(1)


def test_windows_mount_process_receives_vaults_data_dir(tmp_path, monkeypatch):
    manager = _build_manager(tmp_path)
    proc = _FakeProcess()

    captured = {}

    def _fake_popen(*args, **kwargs):
        captured["args"] = args
        captured.update(kwargs)
        return proc

    monkeypatch.setattr(mounts_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        mounts_module.subprocess,
        "CREATE_NEW_PROCESS_GROUP",
        0,
        raising=False,
    )
    monkeypatch.setattr(mounts_module.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(mounts_module.subprocess, "run", lambda *a, **k: None)

    info = manager.mount_and_open(file_ref_id=1, open_in_app=False)

    assert info is not None
    cmd = captured["args"][0]
    assert "--vaults-data-dir" in cmd
    assert cmd[cmd.index("--vaults-data-dir") + 1] == str(
        manager.cache_dir.parent.parent
    )
