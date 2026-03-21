from pathlib import Path

import pytest

from app.core.service.vault_file_service import VaultFileService

TEST_CORPUS_DIR = (
    Path(__file__).resolve().parents[4] / "test_data" / "test_corpus"
)


def _corpus_file(name: str) -> Path:
    path = TEST_CORPUS_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Missing test corpus file: {path}")
    return path


def test_copy_file_creates_second_reference_to_same_entry(
    vault_file_service: VaultFileService,
) -> None:
    source = _corpus_file("aerast_chatdid-integration_main_s.txt")

    vault_file_service.add_file(source, dest_name="chatdid.txt")
    copied = vault_file_service.copy_entry("/chatdid.txt", "/", "chatdid-copy.txt")

    entries = sorted(vault_file_service.list_root_entries(), key=lambda entry: entry.name)

    assert copied.virtual_path == "/chatdid-copy.txt"
    assert [entry.name for entry in entries] == ["chatdid-copy.txt", "chatdid.txt"]
    assert entries[0].file_entry_id == entries[1].file_entry_id


def test_copy_folder_recursively_preserves_structure(
    vault_file_service: VaultFileService,
    folder_service,
) -> None:
    folder_service.create_folder("copies", None)
    source = _corpus_file("bitplane_blkcache_master_claude.md")

    vault_file_service.add_file(
        source,
        dest_name="blkcache.md",
        dest_parent_virtual_path="/docs/2026",
    )

    copied = vault_file_service.copy_entry("/docs", "/copies")
    all_paths = sorted(entry.virtual_path for entry in vault_file_service.list_all_entries())

    assert copied.virtual_path == "/copies/docs"
    assert "/copies/docs" in all_paths
    assert "/copies/docs/2026" in all_paths
    assert "/copies/docs/2026/blkcache.md" in all_paths


def test_move_entries_supports_multiple_sources(
    vault_file_service: VaultFileService,
) -> None:
    first = _corpus_file("aerast_chatdid-integration_main_s.txt")
    second = _corpus_file("bitplane_blkcache_master_claude.md")

    vault_file_service.add_file(first, dest_name="chatdid.txt")
    vault_file_service.add_file(second, dest_name="blkcache.md")

    moved = vault_file_service.move_entries(
        ["/chatdid.txt", "/blkcache.md"],
        "/archive/2026",
    )
    root_paths = sorted(entry.virtual_path for entry in vault_file_service.list_root_entries())
    moved_paths = sorted(entry.virtual_path for entry in moved)

    assert moved_paths == ["/archive/2026/blkcache.md", "/archive/2026/chatdid.txt"]
    assert root_paths == ["/archive"]


def test_copy_entry_creates_missing_destination_folders(
    vault_file_service: VaultFileService,
) -> None:
    source = _corpus_file("aerast_chatdid-integration_main_s.txt")

    vault_file_service.add_file(source, dest_name="chatdid.txt")
    copied = vault_file_service.copy_entry("/chatdid.txt", "/copies/2026")
    all_paths = sorted(entry.virtual_path for entry in vault_file_service.list_all_entries())

    assert copied.virtual_path == "/copies/2026/chatdid.txt"
    assert "/copies" in all_paths
    assert "/copies/2026" in all_paths


def test_rename_and_delete_entries_update_tree(
    vault_file_service: VaultFileService,
) -> None:
    source = _corpus_file("aerast_chatdid-integration_main_s.txt")

    vault_file_service.add_file(
        source,
        dest_name="draft.txt",
        dest_parent_virtual_path="/docs",
    )

    renamed = vault_file_service.rename_entry("/docs/draft.txt", "final.txt")
    deleted = vault_file_service.delete_entries(["/docs"])

    assert renamed.virtual_path == "/docs/final.txt"
    assert deleted == 1
    assert vault_file_service.list_all_entries() == []


def test_export_entries_supports_multiple_files_and_folders(
    vault_file_service: VaultFileService,
    tmp_path: Path,
) -> None:
    alpha = _corpus_file("aerast_chatdid-integration_main_s.txt")
    beta = _corpus_file("bitplane_blkcache_master_claude.md")

    vault_file_service.add_file(alpha, dest_name="chatdid.txt")
    vault_file_service.add_file(
        beta,
        dest_name="blkcache.md",
        dest_parent_virtual_path="/docs",
    )

    export_dir = tmp_path / "exported"
    exported = vault_file_service.export_entries(
        ["/chatdid.txt", "/docs"],
        export_dir,
    )

    assert sorted(path.name for path in exported) == ["chatdid.txt", "docs"]
    assert (export_dir / "chatdid.txt").read_bytes() == alpha.read_bytes()
    assert (export_dir / "docs" / "blkcache.md").read_bytes() == beta.read_bytes()


def test_move_entries_rejects_nested_selection(
    vault_file_service: VaultFileService,
) -> None:
    source = _corpus_file("aerast_chatdid-integration_main_s.txt")

    vault_file_service.add_file(
        source,
        dest_name="child.txt",
        dest_parent_virtual_path="/docs",
    )

    with pytest.raises(ValueError, match="Nested selections"):
        vault_file_service.move_entries(["/docs", "/docs/child.txt"], "/")


def test_delete_entry_keeps_shared_content_when_other_reference_exists(
    vault_file_service: VaultFileService,
) -> None:
    source = _corpus_file("aerast_chatdid-integration_main_s.txt")

    vault_file_service.add_file(source, dest_name="original.txt")
    vault_file_service.copy_entry("/original.txt", "/", "copy.txt")

    deleted = vault_file_service.delete_entries(["/original.txt"])
    remaining = [entry for entry in vault_file_service.list_root_entries() if not entry.is_folder]

    assert deleted == 1
    assert [entry.name for entry in remaining] == ["copy.txt"]
    metadata = vault_file_service.get_file_reference_metadata(remaining[0].id)
    assert metadata["file_name"] == "aerast_chatdid-integration_main_s.txt"
