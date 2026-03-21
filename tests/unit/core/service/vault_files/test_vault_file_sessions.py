from pathlib import Path
from types import SimpleNamespace

import app.core.service.vault_file_sessions as sessions_module
from app.core.service.models import PendingFallbackOpen, VaultContext
from app.core.service.vault_file_sessions import (
    cleanup_unlocked_files,
    list_fallback_unlocked_files,
    list_unlocked_files,
)


class _FakeMounts:
    def __init__(self, active=None) -> None:
        self.active = active or {}
        self.cleaned = False

    def get_active_mounts(self):
        return self.active

    def cleanup_all(self) -> int:
        self.cleaned = True
        return len(self.active)


def test_list_fallback_unlocked_files_maps_pending_entries(tmp_path: Path) -> None:
    temp_path = tmp_path / "report.txt"
    fallback_opens = {
        2: PendingFallbackOpen(
            file_ref_id=2,
            file_name="report.txt",
            temp_path=temp_path,
            original_hash="hash",
            original_mtime=1.0,
            opened_at=20.0,
        )
    }

    result = list_fallback_unlocked_files(fallback_opens)

    assert len(result) == 1
    assert result[0].source == "fallback"
    assert result[0].file_ref_id == 2
    assert result[0].file_path == temp_path


def test_list_unlocked_files_combines_and_sorts_mounts_and_fallbacks(
    tmp_path: Path,
) -> None:
    mounted_path = tmp_path / "mounted.txt"
    context = VaultContext(
        app_data_dir=tmp_path,
        mounts=_FakeMounts(
            {
                1: SimpleNamespace(
                    file_ref_id=1,
                    file_name="mounted.txt",
                    file_path=mounted_path,
                    mounted_at=30.0,
                )
            }
        ),
    )
    temp_path = tmp_path / "fallback.txt"
    fallback_opens = {
        2: PendingFallbackOpen(
            file_ref_id=2,
            file_name="fallback.txt",
            temp_path=temp_path,
            original_hash="hash",
            original_mtime=1.0,
            opened_at=10.0,
        )
    }

    result = list_unlocked_files(context, fallback_opens)

    assert [item.file_ref_id for item in result] == [2, 1]
    assert [item.source for item in result] == ["fallback", "mount"]


def test_cleanup_unlocked_files_finalizes_fallbacks_and_disposes_resources(
    tmp_path: Path,
    monkeypatch,
) -> None:
    mounts = _FakeMounts()
    engine = SimpleNamespace(disposed=False)
    engine.dispose = lambda: setattr(engine, "disposed", True)
    context = VaultContext(
        app_data_dir=tmp_path,
        mounts=mounts,
        db=SimpleNamespace(engine=engine),
    )
    temp_path = tmp_path / "fallback.txt"
    fallback_opens = {
        1: PendingFallbackOpen(
            file_ref_id=1,
            file_name="fallback.txt",
            temp_path=temp_path,
            original_hash="hash",
            original_mtime=1.0,
        )
    }
    finalize_calls: list[int] = []

    def _fake_finalize(*args, **kwargs):
        finalize_calls.append(kwargs["file_ref_id"])
        kwargs["fallback_opens"].pop(kwargs["file_ref_id"], None)
        return "done"

    monkeypatch.setattr(sessions_module, "finalize_fallback_open", _fake_finalize)

    cleanup_unlocked_files(
        context,
        fallback_opens=fallback_opens,
        file_service=SimpleNamespace(),
        folder_service=SimpleNamespace(),
        encryption_service=SimpleNamespace(),
    )

    assert finalize_calls == [1]
    assert fallback_opens == {}
    assert mounts.cleaned is True
    assert engine.disposed is True


def test_cleanup_unlocked_files_logs_and_continues_on_finalize_error(
    tmp_path: Path,
    monkeypatch,
) -> None:
    mounts = _FakeMounts()
    context = VaultContext(app_data_dir=tmp_path, mounts=mounts)
    warnings: list[str] = []
    fallback_opens = {
        1: PendingFallbackOpen(
            file_ref_id=1,
            file_name="fallback.txt",
            temp_path=tmp_path / "fallback.txt",
            original_hash="hash",
            original_mtime=1.0,
        )
    }

    monkeypatch.setattr(
        sessions_module,
        "finalize_fallback_open",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    monkeypatch.setattr(
        sessions_module.logger,
        "warning",
        warnings.append,
    )

    cleanup_unlocked_files(
        context,
        fallback_opens=fallback_opens,
        file_service=SimpleNamespace(),
        folder_service=SimpleNamespace(),
        encryption_service=SimpleNamespace(),
    )

    assert warnings == ["Failed cleanup for fallback file 1: boom"]
    assert mounts.cleaned is True
