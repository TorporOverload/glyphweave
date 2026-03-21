from pathlib import Path
from types import SimpleNamespace
from typing import Any

import app.core.service.vault_file_fallback as fallback_module
from app.core.crypto.service.utils import compute_hash
from app.core.service.models import PendingFallbackOpen, VaultContext
from app.core.service.vault_file_fallback import (
    finalize_fallback_open,
    get_cached_fallback_result,
    open_file_fallback,
)


class _MasterKey:
    def __init__(self, value: bytes) -> None:
        self._value = value

    def get(self) -> bytes:
        return self._value

    def view(self) -> memoryview:
        return memoryview(self._value)


class _FakeEncryptionService:
    def __init__(self, plaintext: bytes) -> None:
        self.plaintext = plaintext
        self.decrypt_calls: list[dict[str, Any]] = []

    def decrypt_file(self, **kwargs: Any) -> None:
        self.decrypt_calls.append(kwargs)
        output_path = kwargs["output_path"]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(self.plaintext)


class _FakeFileService:
    def __init__(self, file_ref: Any) -> None:
        self.file_ref = file_ref
        self.calls: list[int] = []

    def get_file_reference_with_blobs(self, file_ref_id: int) -> Any:
        self.calls.append(file_ref_id)
        return self.file_ref


class _FakeFolderService:
    def __init__(self) -> None:
        self.gc = SimpleNamespace(cleanup_orphaned_entry=lambda entry_id: None)


def _build_context(tmp_path: Path) -> VaultContext:
    vault_path = tmp_path / "vault"
    local_data_path = tmp_path / "local"
    vault_path.mkdir()
    local_data_path.mkdir()
    return VaultContext(
        app_data_dir=tmp_path,
        vault_id="vault-1",
        vault_path=vault_path,
        local_data_path=local_data_path,
        master_key=_MasterKey(b"k" * 32),
    )


def _build_file_ref() -> Any:
    file_entry = SimpleNamespace(
        blobs=[SimpleNamespace(blob_id="blob-1.enc")],
        mime_type="text/plain",
        file_id="file-1",
        original_size_bytes=5,
    )
    return SimpleNamespace(id=1, name="report.txt", file_entry=file_entry)


def test_get_cached_fallback_result_reopens_existing_file(
    tmp_path, monkeypatch
) -> None:
    temp_path = tmp_path / "cached.txt"
    temp_path.write_text("hello", encoding="utf-8")
    fallback_opens = {
        1: PendingFallbackOpen(
            file_ref_id=1,
            file_name="report.txt",
            temp_path=temp_path,
            original_hash="hash",
            original_mtime=temp_path.stat().st_mtime,
        )
    }
    opened_paths: list[Path] = []

    monkeypatch.setattr(fallback_module, "open_with_default_app", opened_paths.append)

    result = get_cached_fallback_result(
        fallback_opens,
        file_ref_id=1,
        file_name="report.txt",
        launch_in_default_app=True,
    )

    assert result is not None
    assert result.file_path == temp_path
    assert result.message == "Reopened cached decrypted file"
    assert opened_paths == [temp_path]


def test_open_file_fallback_decrypts_and_tracks_pending(tmp_path, monkeypatch) -> None:
    context = _build_context(tmp_path)
    fallback_opens: dict[int, PendingFallbackOpen] = {}
    file_ref = _build_file_ref()
    file_service = _FakeFileService(file_ref)
    encryption_service = _FakeEncryptionService(b"hello")
    opened_paths: list[Path] = []

    monkeypatch.setattr(fallback_module, "open_with_default_app", opened_paths.append)

    result = open_file_fallback(
        context,
        fallback_opens=fallback_opens,
        file_service=file_service,
        encryption_service=encryption_service,
        file_ref=file_ref,
        launch_in_default_app=True,
    )

    pending = fallback_opens[file_ref.id]

    assert result.source == "fallback"
    assert result.file_path == pending.temp_path
    assert pending.temp_path.read_bytes() == b"hello"
    assert opened_paths == [pending.temp_path]
    assert file_service.calls == [file_ref.id]
    assert len(encryption_service.decrypt_calls) == 1


def test_finalize_fallback_open_cleans_up_unchanged_file(tmp_path) -> None:
    context = _build_context(tmp_path)
    temp_path = tmp_path / "local" / "cache" / "decrypted-files" / "report.txt"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path.write_text("hello", encoding="utf-8")
    fallback_opens = {
        1: PendingFallbackOpen(
            file_ref_id=1,
            file_name="report.txt",
            temp_path=temp_path,
            original_hash=compute_hash(temp_path),
            original_mtime=temp_path.stat().st_mtime,
        )
    }

    result = finalize_fallback_open(
        context,
        fallback_opens=fallback_opens,
        file_service=_FakeFileService(None),
        folder_service=_FakeFolderService(),
        encryption_service=_FakeEncryptionService(b""),
        file_ref_id=1,
    )

    assert result == "No changes detected. File unmounted"
    assert 1 not in fallback_opens
    assert not temp_path.exists()


def test_finalize_fallback_open_reencrypts_changed_file(tmp_path, monkeypatch) -> None:
    context = _build_context(tmp_path)
    file_ref = _build_file_ref()
    temp_path = tmp_path / "local" / "cache" / "decrypted-files" / "report.txt"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path.write_text("updated", encoding="utf-8")
    fallback_opens = {
        1: PendingFallbackOpen(
            file_ref_id=1,
            file_name="report.txt",
            temp_path=temp_path,
            original_hash="old-hash",
            original_mtime=0.0,
        )
    }
    calls: list[dict[str, Any]] = []

    monkeypatch.setattr(
        fallback_module,
        "re_encrypt_file",
        lambda *args, **kwargs: calls.append(kwargs),
    )

    result = finalize_fallback_open(
        context,
        fallback_opens=fallback_opens,
        file_service=_FakeFileService(file_ref),
        folder_service=_FakeFolderService(),
        encryption_service=_FakeEncryptionService(b""),
        file_ref_id=1,
    )

    assert result == "Changes saved to vault and file unmounted"
    assert len(calls) == 1
    assert calls[0]["file_ref"] is file_ref
    assert calls[0]["plaintext_path"] == temp_path
    assert 1 not in fallback_opens
    assert not temp_path.exists()
