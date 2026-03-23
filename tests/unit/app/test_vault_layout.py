from pathlib import Path

from app.common.paths.vault_layout import (
    blobs_dir,
    create_vault_layout,
    resolve_blob_path,
    writable_blobs_dir,
)


def test_ensure_vault_layout_creates_expected_directories(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"

    create_vault_layout(vault_path)

    assert vault_path.exists()
    assert (vault_path / "blobs").exists()
    assert (vault_path / "events").exists()
    assert (vault_path / "db_dumps").exists()


def test_resolve_blob_path_prefers_blobs_directory(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    blob_store = writable_blobs_dir(vault_path)
    (blob_store / "a.enc").write_bytes(b"modern")

    assert resolve_blob_path(vault_path, "a.enc") == blobs_dir(vault_path) / "a.enc"


def test_resolve_blob_path_uses_blobs_directory_only(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    writable_blobs_dir(vault_path)

    assert resolve_blob_path(vault_path, "b.enc") == blobs_dir(vault_path) / "b.enc"
