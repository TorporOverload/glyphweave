"""Integration test for the full file lifecycle through VaultFileService.

add_file -> open_file_by_ref (fallback) -> modify temp -> unmount (save) ->
reopen and verify new content.
"""

from pathlib import Path

import pytest

from app.core.service.vault_file_service import VaultFileService


class TestFileLifecycle:
    def test_add_open_modify_save_reopen(
        self,
        vault_file_service: VaultFileService,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        """Full lifecycle: import -> open (fallback) -> edit -> save -> verify."""
        # Prevent the launcher from actually opening a desktop app
        import app.core.service.vault_file_fallback as fb_mod

        monkeypatch.setattr(fb_mod, "open_with_default_app", lambda _: None)

        # --- Step 1: Import a file into the vault ---
        source = tmp_path / "original.txt"
        original_content = b"Hello, GlyphWeave lifecycle test!"
        source.write_bytes(original_content)

        result = vault_file_service.add_file(source, dest_name="lifecycle.txt")
        assert result.file_name == "lifecycle.txt"
        assert result.blob_count >= 1

        # --- Step 2: Find the file reference ---
        entries = vault_file_service.list_root_entries()
        file_refs = [e for e in entries if not e.is_folder]
        assert len(file_refs) == 1
        ref = file_refs[0]
        assert ref.name == "lifecycle.txt"

        # --- Step 3: Open via fallback (no FUSE mounts configured) ---
        open_result = vault_file_service.open_file_by_ref(
            ref.id, launch_in_default_app=False
        )
        assert open_result.opened is True
        assert open_result.source == "fallback"
        assert open_result.file_path is not None
        assert open_result.file_path.exists()
        assert open_result.file_path.read_bytes() == original_content

        # Verify the file appears in unlocked list
        unlocked = vault_file_service.list_unlocked_files()
        assert any(u.file_ref_id == ref.id for u in unlocked)

        # --- Step 4: Modify the decrypted temp file ---
        modified_content = b"Modified content after edit!"
        open_result.file_path.write_bytes(modified_content)

        # --- Step 5: Unmount (finalize) — should detect changes and re-encrypt ---
        save_msg = vault_file_service.unmount_unlocked(ref.id)
        assert "Changes saved" in save_msg

        # Temp file should be cleaned up
        assert not open_result.file_path.exists()

        # File should no longer appear in unlocked list
        unlocked_after = vault_file_service.list_unlocked_files()
        assert not any(u.file_ref_id == ref.id for u in unlocked_after)

        # --- Step 6: Reopen and verify the modified content persisted ---
        reopen_result = vault_file_service.open_file_by_ref(
            ref.id, launch_in_default_app=False
        )
        assert reopen_result.opened is True
        assert reopen_result.source == "fallback"
        assert reopen_result.file_path.read_bytes() == modified_content

        # Clean up
        vault_file_service.unmount_unlocked(ref.id)

    def test_add_open_unmount_unchanged(
        self,
        vault_file_service: VaultFileService,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        """Verify that unmounting an unmodified file skips re-encryption."""
        import app.core.service.vault_file_fallback as fb_mod

        monkeypatch.setattr(fb_mod, "open_with_default_app", lambda _: None)

        source = tmp_path / "readonly.txt"
        source.write_bytes(b"Read-only content")

        vault_file_service.add_file(source, dest_name="readonly.txt")
        entries = vault_file_service.list_root_entries()
        ref = [e for e in entries if e.name == "readonly.txt"][0]

        open_result = vault_file_service.open_file_by_ref(
            ref.id, launch_in_default_app=False
        )
        assert open_result.file_path.read_bytes() == b"Read-only content"

        # Unmount without modification
        msg = vault_file_service.unmount_unlocked(ref.id)
        assert "No changes" in msg
        assert not open_result.file_path.exists()

    def test_add_deduplicates_identical_content(
        self,
        vault_file_service: VaultFileService,
        tmp_path: Path,
    ) -> None:
        """Importing the same content twice should deduplicate."""
        source = tmp_path / "dup.txt"
        source.write_bytes(b"Duplicate content")

        r1 = vault_file_service.add_file(source, dest_name="copy1.txt")
        r2 = vault_file_service.add_file(source, dest_name="copy2.txt")

        assert r1.deduplicated is False
        assert r2.deduplicated is True

        entries = vault_file_service.list_root_entries()
        names = sorted(e.name for e in entries if not e.is_folder)
        assert "copy1.txt" in names
        assert "copy2.txt" in names

    def test_cleanup_finalizes_all_fallback_opens(
        self,
        vault_file_service: VaultFileService,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        """cleanup() should finalize all open fallback files."""
        import app.core.service.vault_file_fallback as fb_mod

        monkeypatch.setattr(fb_mod, "open_with_default_app", lambda _: None)

        source = tmp_path / "cleanup.txt"
        source.write_bytes(b"Cleanup test")

        vault_file_service.add_file(source, dest_name="cleanup.txt")
        entries = vault_file_service.list_root_entries()
        ref = [e for e in entries if e.name == "cleanup.txt"][0]

        open_result = vault_file_service.open_file_by_ref(
            ref.id, launch_in_default_app=False
        )
        assert open_result.file_path.exists()

        vault_file_service.cleanup()

        assert not open_result.file_path.exists()
        assert len(vault_file_service.fallback_opens) == 0
