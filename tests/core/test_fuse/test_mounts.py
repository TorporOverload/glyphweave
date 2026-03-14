"""
Tests for Mounts - orchestrates on-demand single-file FUSE mounts.

Note: These tests focus on the Mounts logic without requiring actual
FUSE mounting (which needs elevated permissions). FUSE operations are mocked.
"""

import os
import pytest
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

from app.core.database.model.WAL_entry import WalEntry
from app.core.database.model.file_entry import FileEntry
from app.core.database.model.file_reference import FileReference
from app.core.database.model.file_blob_reference import FileBlobReference
from app.core.fuse.fuse_orchestrator import FuseOrchestrator, MountInfo
from app.core.vault_layout import resolve_blob_path


class TestMountsInit:
    """Test Mounts initialization."""

    def test_init_creates_cache_directories(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        """Test that Mounts creates required directories on init."""
        cache_dir = temp_runtime_cache_dir

        with patch.object(FuseOrchestrator, "_check_and_recover"):
            manager = FuseOrchestrator(
                cache_dir=cache_dir,
                vault_path=temp_vault_path,
                db_session=db_session,
                key_service=key_service,
                vault_id=test_vault_id,
                master_key=test_master_key,
                auto_recover=False,
            )

        assert cache_dir.exists()
        assert (cache_dir / "fuse-mounts").exists()

    def test_init_with_auto_recover_calls_recovery(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        """Test that auto_recover=True triggers crash recovery."""
        cache_dir = temp_runtime_cache_dir

        with patch.object(FuseOrchestrator, "_check_and_recover") as mock_recover:
            FuseOrchestrator(
                cache_dir=cache_dir,
                vault_path=temp_vault_path,
                db_session=db_session,
                key_service=key_service,
                vault_id=test_vault_id,
                master_key=test_master_key,
                auto_recover=True,
            )

        mock_recover.assert_called_once()

    def test_init_without_auto_recover(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        """Test that auto_recover=False skips crash recovery."""
        cache_dir = temp_runtime_cache_dir

        with patch.object(FuseOrchestrator, "_check_and_recover") as mock_recover:
            FuseOrchestrator(
                cache_dir=cache_dir,
                vault_path=temp_vault_path,
                db_session=db_session,
                key_service=key_service,
                vault_id=test_vault_id,
                master_key=test_master_key,
                auto_recover=False,
            )

        mock_recover.assert_not_called()


class TestMountsRecovery:
    """Test crash recovery functionality."""

    def test_recovery_with_no_pending_entries(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        """Test recovery when there are no unflushed WAL entries."""
        cache_dir = temp_runtime_cache_dir

        # Create manager - recovery should complete without error
        manager = FuseOrchestrator(
            cache_dir=cache_dir,
            vault_path=temp_vault_path,
            db_session=db_session,
            key_service=key_service,
            vault_id=test_vault_id,
            master_key=test_master_key,
            auto_recover=True,
        )

        # No pending entries, nothing to recover
        assert manager.wal_service.count_pending() == 0

    def test_recovery_cleans_up_orphaned_temp_blobs(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
        temp_store,
    ):
        """Test that recovery cleans up orphaned temp blobs not in WAL."""
        cache_dir = temp_runtime_cache_dir

        # Manually create orphaned temp blobs (not referenced by any WalEntry)
        orphan_blob = temp_store.write_temp_blob("orphan_file", 0, b"orphaned data")

        # Verify orphan exists
        assert (temp_store.tmp_dir / f"{orphan_blob}.enc").exists()

        # Create manager - recovery should clean up orphaned blobs
        manager = FuseOrchestrator(
            cache_dir=cache_dir,
            vault_path=temp_vault_path,
            db_session=db_session,
            key_service=key_service,
            vault_id=test_vault_id,
            master_key=test_master_key,
            auto_recover=True,
        )

        # Orphan blob should be cleaned up
        assert not (temp_store.tmp_dir / f"{orphan_blob}.enc").exists()

    def test_recovery_with_valid_pending_entries(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        encryption_service,
        file_service,
        test_vault_id,
        test_master_key,
        wal_service,
        temp_store,
        sample_small_file,
    ):
        """Test recovery replays valid pending WAL entries."""
        import hashlib
        import secrets

        cache_dir = temp_runtime_cache_dir
        file_path, original_content = sample_small_file
        file_id = secrets.token_hex(16)

        # Encrypt the file
        blob_ids = encryption_service.encrypt_file(
            file_path=file_path,
            vault_path=temp_vault_path,
            master_key=test_master_key,
            vault_id=test_vault_id,
            file_id=file_id,
        )

        # Create FileEntry
        content_hash = hashlib.sha256(original_content).hexdigest()
        encrypted_size = sum(
            resolve_blob_path(temp_vault_path, bid).stat().st_size for bid in blob_ids
        )

        file_entry = file_service.create_file_entry_with_blobs(
            file_id=file_id,
            content_hash=content_hash,
            mime_type="text/plain",
            encrypted_size=encrypted_size,
            original_size=len(original_content),
            blob_ids=blob_ids,
        )

        # Create FileReference
        file_ref = file_service.create_file_reference(
            name="recovery_test.txt",
            parent_id=None,
            file_entry_id=file_entry.id,
        )
        db_session.commit()

        # Simulate a crash by creating unflushed WAL entries
        new_data = b"Modified content after crash"
        wal_service.log_write(
            file_ref_id=file_ref.id,
            chunk_index=0,
            offset=0,
            length=len(new_data),
            data=new_data,
            file_id=file_id,
        )
        db_session.commit()

        assert wal_service.count_pending() == 1

        # Create manager - recovery should replay the pending write
        manager = FuseOrchestrator(
            cache_dir=cache_dir,
            vault_path=temp_vault_path,
            db_session=db_session,
            key_service=key_service,
            vault_id=test_vault_id,
            master_key=test_master_key,
            auto_recover=True,
        )

        # After recovery, no pending entries
        assert wal_service.count_pending() == 0


class TestMountsMounting:
    """Test mount and unmount operations."""

    def test_mount_returns_none_for_nonexistent_file(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        """Test that mounting a non-existent file returns None."""
        cache_dir = temp_runtime_cache_dir

        with patch.object(FuseOrchestrator, "_check_and_recover"):
            manager = FuseOrchestrator(
                cache_dir=cache_dir,
                vault_path=temp_vault_path,
                db_session=db_session,
                key_service=key_service,
                vault_id=test_vault_id,
                master_key=test_master_key,
                auto_recover=False,
            )

        result = manager.mount_and_open(file_ref_id=999, open_in_app=False)
        assert result is None

    def test_is_mounted_returns_false_initially(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        """Test is_mounted returns False for unmounted files."""
        cache_dir = temp_runtime_cache_dir

        with patch.object(FuseOrchestrator, "_check_and_recover"):
            manager = FuseOrchestrator(
                cache_dir=cache_dir,
                vault_path=temp_vault_path,
                db_session=db_session,
                key_service=key_service,
                vault_id=test_vault_id,
                master_key=test_master_key,
                auto_recover=False,
            )

        assert manager.is_mounted(file_ref_id=1) is False

    def test_get_mounted_path_returns_none_for_unmounted(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        """Test get_mounted_path returns None for unmounted files."""
        cache_dir = temp_runtime_cache_dir

        with patch.object(FuseOrchestrator, "_check_and_recover"):
            manager = FuseOrchestrator(
                cache_dir=cache_dir,
                vault_path=temp_vault_path,
                db_session=db_session,
                key_service=key_service,
                vault_id=test_vault_id,
                master_key=test_master_key,
                auto_recover=False,
            )

        assert manager.get_mounted_path(file_ref_id=1) is None

    def test_active_mount_count_initially_zero(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        """Test active_mount_count is zero initially."""
        cache_dir = temp_runtime_cache_dir

        with patch.object(FuseOrchestrator, "_check_and_recover"):
            manager = FuseOrchestrator(
                cache_dir=cache_dir,
                vault_path=temp_vault_path,
                db_session=db_session,
                key_service=key_service,
                vault_id=test_vault_id,
                master_key=test_master_key,
                auto_recover=False,
            )

        assert manager.active_mount_count == 0

    def test_get_active_mounts_returns_empty_dict(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        """Test get_active_mounts returns empty dict initially."""
        cache_dir = temp_runtime_cache_dir

        with patch.object(FuseOrchestrator, "_check_and_recover"):
            manager = FuseOrchestrator(
                cache_dir=cache_dir,
                vault_path=temp_vault_path,
                db_session=db_session,
                key_service=key_service,
                vault_id=test_vault_id,
                master_key=test_master_key,
                auto_recover=False,
            )

        assert manager.get_active_mounts() == {}

    def test_unmount_nonexistent_returns_false(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        """Test unmount returns False for non-mounted file."""
        cache_dir = temp_runtime_cache_dir

        with patch.object(FuseOrchestrator, "_check_and_recover"):
            manager = FuseOrchestrator(
                cache_dir=cache_dir,
                vault_path=temp_vault_path,
                db_session=db_session,
                key_service=key_service,
                vault_id=test_vault_id,
                master_key=test_master_key,
                auto_recover=False,
            )

        result = manager.unmount(file_ref_id=999)
        assert result is False


class TestMountsCleanup:
    """Test cleanup operations."""

    def test_cleanup_all_with_no_mounts(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        """Test cleanup_all with no active mounts."""
        cache_dir = temp_runtime_cache_dir

        with patch.object(FuseOrchestrator, "_check_and_recover"):
            manager = FuseOrchestrator(
                cache_dir=cache_dir,
                vault_path=temp_vault_path,
                db_session=db_session,
                key_service=key_service,
                vault_id=test_vault_id,
                master_key=test_master_key,
                auto_recover=False,
            )

        cleaned = manager.cleanup_all()
        assert cleaned == 0

    def test_cleanup_all_recreates_mount_base(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        """Test that cleanup_all recreates the mount_base directory."""
        cache_dir = temp_runtime_cache_dir

        with patch.object(FuseOrchestrator, "_check_and_recover"):
            manager = FuseOrchestrator(
                cache_dir=cache_dir,
                vault_path=temp_vault_path,
                db_session=db_session,
                key_service=key_service,
                vault_id=test_vault_id,
                master_key=test_master_key,
                auto_recover=False,
            )

        mount_base = manager.mount_base
        assert mount_base.exists()

        # Add some files to mount_base to verify cleanup
        (mount_base / "test_file").write_text("test")

        manager.cleanup_all()

        # Mount base should still exist but be empty
        assert mount_base.exists()
        assert not (mount_base / "test_file").exists()


class TestMountInfo:
    """Test MountInfo dataclass."""

    def test_mount_info_creation(self, temp_vault_path):
        """Test creating a MountInfo instance."""
        mount_dir = temp_vault_path / "mount"
        file_path = mount_dir / "test.txt"

        mock_fs = MagicMock()
        mock_thread = MagicMock()

        info = MountInfo(
            file_ref_id=1,
            file_name="test.txt",
            mount_dir=mount_dir,
            file_path=file_path,
            fs=mock_fs,
            thread=mock_thread,
        )

        assert info.file_ref_id == 1
        assert info.file_name == "test.txt"
        assert info.mount_dir == mount_dir
        assert info.file_path == file_path
        assert info.fs is mock_fs
        assert info.thread is mock_thread
        assert info.mounted_at > 0


class TestMountFileNaming:
    def test_mount_file_name_uses_mime_extension_when_missing_suffix(self):
        mount_dir = Path("C:/tmp/mount")
        name = FuseOrchestrator._mount_file_name(
            "report",
            1,
            mount_dir,
            mime_type="text/plain",
        )

        assert name == "report.txt"

    def test_mount_file_name_uses_mime_extension_when_missing(self):
        mount_dir = Path("C:/tmp/mount")
        with patch(
            "app.core.fuse.fuse_orchestrator.platform.system", return_value="Windows"
        ):
            name = FuseOrchestrator._mount_file_name(
                "report",
                1,
                mount_dir,
                mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )

        assert name.endswith(".docx")

    def test_mount_file_name_falls_back_to_bin_when_mime_unknown(self):
        mount_dir = Path("C:/tmp/mount")
        with patch(
            "app.core.fuse.fuse_orchestrator.platform.system", return_value="Windows"
        ):
            name = FuseOrchestrator._mount_file_name(
                "report",
                1,
                mount_dir,
                mime_type="application/x-unknown-custom",
            )

        assert name.endswith(".bin")


class TestPlatformSupport:
    def test_fuse_orchestrator_rejects_non_windows(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        cache_dir = temp_runtime_cache_dir

        with patch(
            "app.core.fuse.fuse_orchestrator.platform.system", return_value="Linux"
        ):
            with pytest.raises(OSError, match="Windows"):
                FuseOrchestrator(
                    cache_dir=cache_dir,
                    vault_path=temp_vault_path,
                    db_session=db_session,
                    key_service=key_service,
                    vault_id=test_vault_id,
                    master_key=test_master_key,
                    auto_recover=False,
                )


class TestMountsThreadSafety:
    """Test thread safety of Mounts operations."""

    def test_concurrent_is_mounted_calls(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        """Test that concurrent is_mounted calls are thread-safe."""
        cache_dir = temp_runtime_cache_dir

        with patch.object(FuseOrchestrator, "_check_and_recover"):
            manager = FuseOrchestrator(
                cache_dir=cache_dir,
                vault_path=temp_vault_path,
                db_session=db_session,
                key_service=key_service,
                vault_id=test_vault_id,
                master_key=test_master_key,
                auto_recover=False,
            )

        results = []
        errors = []

        def check_mounted():
            try:
                for _ in range(100):
                    result = manager.is_mounted(1)
                    results.append(result)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=check_mounted) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert all(r is False for r in results)

    def test_concurrent_get_active_mounts(
        self,
        temp_vault_path,
        temp_runtime_cache_dir,
        db_session,
        key_service,
        test_vault_id,
        test_master_key,
    ):
        """Test that concurrent get_active_mounts calls are thread-safe."""
        cache_dir = temp_runtime_cache_dir

        with patch.object(FuseOrchestrator, "_check_and_recover"):
            manager = FuseOrchestrator(
                cache_dir=cache_dir,
                vault_path=temp_vault_path,
                db_session=db_session,
                key_service=key_service,
                vault_id=test_vault_id,
                master_key=test_master_key,
                auto_recover=False,
            )

        results = []
        errors = []

        def get_mounts():
            try:
                for _ in range(100):
                    result = manager.get_active_mounts()
                    results.append(result)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=get_mounts) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert all(r == {} for r in results)
