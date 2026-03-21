"""
Tests for SingleFileFS - single-file FUSE filesystem.

These tests exercise the FUSE operations logic without actually mounting
the filesystem (which would require elevated permissions).
"""

import os
import stat

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


class TestSingleFileFS:
    """Test suite for SingleFileFS."""

    def test_getattr_root(self, single_fs):
        """Test getattr for root directory."""
        fs, _ = single_fs

        attrs = fs.getattr("/")

        assert attrs["st_mode"] & stat.S_IFDIR
        assert attrs["st_nlink"] == 2

    def test_getattr_file(self, single_fs):
        """Test getattr for the mounted file."""
        fs, original_content = single_fs

        attrs = fs.getattr(f"/{fs.file_name}")

        assert attrs["st_mode"] & stat.S_IFREG
        assert attrs["st_size"] == len(original_content)
        assert attrs["st_nlink"] == 1

    def test_getattr_nonexistent(self, single_fs):
        """Test getattr for nonexistent path."""
        fs, _ = single_fs

        import errno

        from mfusepy import FuseOSError

        with pytest.raises(FuseOSError) as exc:
            fs.getattr("/nonexistent.txt")
        assert exc.value.errno == errno.ENOENT

    def test_readdir(self, single_fs):
        """Test readdir lists the file."""
        fs, _ = single_fs

        entries = fs.readdir("/", fh=0)

        assert "." in entries
        assert ".." in entries
        assert fs.file_name in entries

    def test_open_and_read(self, single_fs):
        """Test opening and reading the file."""
        fs, original_content = single_fs

        # Open
        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        assert fh > 0

        # Read all content
        data = fs.read(f"/{fs.file_name}", len(original_content), 0, fh)
        assert data == original_content

        # Close
        fs.release(f"/{fs.file_name}", fh)

    def test_read_partial(self, single_fs):
        """Test reading part of the file."""
        fs, original_content = single_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)

        # Read middle portion
        offset = 10
        size = 20
        data = fs.read(f"/{fs.file_name}", size, offset, fh)
        assert data == original_content[offset : offset + size]

        fs.release(f"/{fs.file_name}", fh)

    def test_read_beyond_eof(self, single_fs):
        """Test reading beyond end of file returns empty."""
        fs, original_content = single_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)

        # Read past end
        data = fs.read(f"/{fs.file_name}", 100, len(original_content) + 100, fh)
        assert data == b""

        fs.release(f"/{fs.file_name}", fh)

    def test_write_and_read_back(self, single_fs):
        """Test writing data and reading it back."""
        fs, original_content = single_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)

        # Write new data at offset 0
        new_data = b"REPLACED"
        written = fs.write(f"/{fs.file_name}", new_data, 0, fh)
        assert written == len(new_data)

        # Read back
        read_data = fs.read(f"/{fs.file_name}", len(new_data), 0, fh)
        assert read_data == new_data

        # Rest of file should be unchanged
        rest_offset = len(new_data)
        rest_data = fs.read(
            f"/{fs.file_name}",
            len(original_content) - rest_offset,
            rest_offset,
            fh,
        )
        assert rest_data == original_content[rest_offset:]

        fs.release(f"/{fs.file_name}", fh)

    def test_write_extends_file(self, single_fs):
        """Test that writing beyond EOF extends the file."""
        fs, original_content = single_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)

        original_size = len(original_content)
        extend_data = b"EXTENDED DATA"
        extend_offset = original_size + 10  # Leave a gap

        written = fs.write(f"/{fs.file_name}", extend_data, extend_offset, fh)
        assert written == len(extend_data)

        # File size should have grown
        new_size = extend_offset + len(extend_data)
        attrs = fs.getattr(f"/{fs.file_name}", fh)
        assert attrs["st_size"] == new_size

        fs.release(f"/{fs.file_name}", fh)

    def test_truncate_shrink(self, single_fs):
        """Test truncating file to smaller size."""
        fs, original_content = single_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)

        new_size = 10
        fs.truncate(f"/{fs.file_name}", new_size, fh)

        attrs = fs.getattr(f"/{fs.file_name}", fh)
        assert attrs["st_size"] == new_size

        # Read should return truncated content
        data = fs.read(f"/{fs.file_name}", 100, 0, fh)
        assert data == original_content[:new_size]

        fs.release(f"/{fs.file_name}", fh)

    def test_truncate_extend(self, single_fs):
        """Test truncating file to larger size (extends with zeros)."""
        fs, original_content = single_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)

        new_size = len(original_content) + 100
        fs.truncate(f"/{fs.file_name}", new_size, fh)

        attrs = fs.getattr(f"/{fs.file_name}", fh)
        assert attrs["st_size"] == new_size

        fs.release(f"/{fs.file_name}", fh)

    def test_multiple_opens(self, single_fs):
        """Test opening the same file multiple times."""
        fs, original_content = single_fs

        fh1 = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        fh2 = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)

        assert fh1 != fh2
        assert fs._open_count == 2

        # Both can read
        data1 = fs.read(f"/{fs.file_name}", 10, 0, fh1)
        data2 = fs.read(f"/{fs.file_name}", 10, 0, fh2)
        assert data1 == data2 == original_content[:10]

        fs.release(f"/{fs.file_name}", fh1)
        assert fs._open_count == 1

        fs.release(f"/{fs.file_name}", fh2)
        assert fs._open_count == 0

    def test_statfs(self, single_fs):
        """Test statfs returns filesystem info."""
        fs, _ = single_fs

        stats = fs.statfs("/")

        assert "f_bsize" in stats
        assert "f_files" in stats
        assert stats["f_files"] == 2  # root dir + file

    def test_chmod(self, single_fs):
        """Test changing file permissions."""
        fs, _ = single_fs

        new_mode = 0o755
        fs.chmod(f"/{fs.file_name}", new_mode)

        attrs = fs.getattr(f"/{fs.file_name}")
        assert attrs["st_mode"] & 0o777 == new_mode

    def test_utimens(self, single_fs):
        """Test updating file timestamps."""
        fs, _ = single_fs

        new_atime = 1234567890.0
        new_mtime = 1234567891.0

        fs.utimens(f"/{fs.file_name}", times=(new_atime, new_mtime))

        assert fs.metadata.accessed_at == new_atime
        assert fs.metadata.modified_at == new_mtime

    def test_create_temp_file(self, single_fs):
        """Test that temp files can be created for atomic save."""
        fs, _ = single_fs

        fh = fs.create("/temp_file.txt", mode=0o644)
        assert fh >= 10_000  # temp fh counter starts high

    def test_create_over_main_file_raises(self, single_fs):
        """Test that creating over the main file raises EEXIST."""
        fs, _ = single_fs

        import errno

        from mfusepy import FuseOSError

        with pytest.raises(FuseOSError) as exc:
            fs.create(f"/{fs.file_name}", mode=0o644)
        assert exc.value.errno == errno.EEXIST

    def test_unsupported_unlink(self, single_fs):
        """Test that unlink is not supported."""
        fs, _ = single_fs

        import errno

        from mfusepy import FuseOSError

        with pytest.raises(FuseOSError) as exc:
            fs.unlink(f"/{fs.file_name}")
        assert exc.value.errno == errno.EACCES

    def test_unsupported_mkdir(self, single_fs):
        """Test that mkdir is not supported."""
        fs, _ = single_fs

        import errno

        from mfusepy import FuseOSError

        with pytest.raises(FuseOSError) as exc:
            fs.mkdir("/new_dir", mode=0o755)
        assert exc.value.errno == errno.EACCES

    def test_flush_writes_to_wal(self, single_fs, db_session):
        """Test that writes are logged to WAL."""
        fs, _ = single_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)

        # Write some data
        fs.write(f"/{fs.file_name}", b"Test data", 0, fh)

        # Check WAL has pending entries
        assert fs.wal_service.has_pending_writes(fs.file_ref_id)

        fs.release(f"/{fs.file_name}", fh)

    def test_release_checkpoints_wal(self, single_fs, db_session):
        """Test that release checkpoints the WAL."""
        fs, _ = single_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)

        # Write some data
        fs.write(f"/{fs.file_name}", b"Test data", 0, fh)
        assert fs.wal_service.has_pending_writes(fs.file_ref_id)

        # Release should flush and checkpoint
        fs.release(f"/{fs.file_name}", fh)

        # WAL should be clean after checkpoint
        assert not fs.wal_service.has_pending_writes(fs.file_ref_id)

    def test_chunk_store_stages_plaintext_in_runtime_cache(
        self,
        chunk_store,
        monkeypatch,
        temp_vault_path,
    ):
        """Encrypted writes should stage plaintext under the runtime cache only."""
        captured = {}

        def fake_encrypt_file(
            *,
            file_path,
            vault_path,
            master_key,
            vault_id,
            file_id,
        ):
            del master_key, vault_id, file_id
            captured["file_path"] = Path(file_path)
            captured["vault_path"] = Path(vault_path)
            assert captured["file_path"].parent == chunk_store.cache_dir / ".tmp"
            assert captured["vault_path"] == temp_vault_path
            assert captured["file_path"].exists()
            return []

        monkeypatch.setattr(
            chunk_store.encryption_service,
            "encrypt_file",
            fake_encrypt_file,
        )
        monkeypatch.setattr(
            chunk_store.file_service,
            "create_file_entry_with_blobs",
            lambda **kwargs: SimpleNamespace(id=1),
        )

        chunk_store._encrypt_and_store(
            plaintext=b"runtime plaintext",
            file_id="new_file_id",
            content_hash="hash",
            mime_type="text/plain",
        )

        assert captured["file_path"].parent == chunk_store.cache_dir / ".tmp"
        assert not captured["file_path"].exists()
        assert not (temp_vault_path / "blobs" / ".tmp").exists()

    def test_release_keeps_wal_pending_when_blob_flush_fails(
        self, single_fs, monkeypatch
    ):
        fs, _ = single_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)
        fs.write(f"/{fs.file_name}", b"Test data", 0, fh)
        assert fs.wal_service.has_pending_writes(fs.file_ref_id)

        monkeypatch.setattr(
            fs.chunk_store,
            "flush_to_blobs",
            lambda **kwargs: (_ for _ in ()).throw(RuntimeError("flush failed")),
        )
        fs.wal_service.mark_flushed = MagicMock()
        fs.wal_service.checkpoint = MagicMock()

        import errno

        from mfusepy import FuseOSError

        with pytest.raises(FuseOSError) as exc:
            fs.release(f"/{fs.file_name}", fh)
        assert exc.value.errno == errno.EIO

        assert fs.wal_service.has_pending_writes(fs.file_ref_id)
        fs.wal_service.mark_flushed.assert_not_called()
        fs.wal_service.checkpoint.assert_not_called()


class TestSingleFileFSLargeFile:
    """Tests specifically for large multi-chunk files."""

    def test_read_large_file_full(self, large_file_fs):
        """Test reading entire large file."""
        fs, original_content = large_file_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)

        # Read in chunks to avoid memory issues
        chunk_size = 64 * 1024
        offset = 0
        data = bytearray()

        while offset < len(original_content):
            chunk = fs.read(f"/{fs.file_name}", chunk_size, offset, fh)
            if not chunk:
                break
            data.extend(chunk)
            offset += len(chunk)

        assert bytes(data) == original_content

        fs.release(f"/{fs.file_name}", fh)

    def test_read_large_file_cross_chunk(self, large_file_fs):
        """Test reading across chunk boundaries."""
        fs, original_content = large_file_fs
        chunk_size = fs.chunk_size

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)

        # Read starting in middle of first chunk, spanning into second
        offset = chunk_size - 100
        size = 200  # Crosses chunk boundary

        data = fs.read(f"/{fs.file_name}", size, offset, fh)
        assert data == original_content[offset : offset + size]

        fs.release(f"/{fs.file_name}", fh)

    def test_write_large_file_cross_chunk(self, large_file_fs):
        """Test writing across chunk boundaries."""
        fs, original_content = large_file_fs
        chunk_size = fs.chunk_size

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)

        # Write across chunk boundary
        offset = chunk_size - 50
        new_data = b"X" * 100  # Spans 50 bytes into two chunks

        written = fs.write(f"/{fs.file_name}", new_data, offset, fh)
        assert written == len(new_data)

        # Read back and verify
        read_data = fs.read(f"/{fs.file_name}", len(new_data), offset, fh)
        assert read_data == new_data

        fs.release(f"/{fs.file_name}", fh)

    def test_random_access_reads(self, large_file_fs):
        """Test random access reading patterns."""
        fs, original_content = large_file_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)

        # Read from various offsets
        test_reads = [
            (0, 100),  # Start
            (len(original_content) - 100, 100),  # End
            (50000, 200),  # Middle
            (64 * 1024, 100),  # Chunk boundary
            (128 * 1024 - 50, 100),  # Cross boundary
        ]

        for offset, size in test_reads:
            if offset + size > len(original_content):
                size = len(original_content) - offset
            if offset >= len(original_content):
                continue

            data = fs.read(f"/{fs.file_name}", size, offset, fh)
            expected = original_content[offset : offset + size]
            if offset >= len(original_content):
                continue

            data = fs.read(f"/{fs.file_name}", size, offset, fh)
            expected = original_content[offset : offset + size]
            assert data == expected, f"Mismatch at offset {offset}"

        fs.release(f"/{fs.file_name}", fh)


class TestSingleFileFSRoundtrip:
    """Tests for write → flush → reopen → read-back data persistence."""

    def test_write_release_reopen_roundtrip(self, single_fs):
        """Write new content, release (flush to blobs), reopen, read back."""
        fs, original_content = single_fs
        new_content = b"Completely new file content after editing!"

        # Write phase
        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)
        fs.write(f"/{fs.file_name}", new_content, 0, fh)
        fs.truncate(f"/{fs.file_name}", len(new_content), fh)
        fs.release(f"/{fs.file_name}", fh)

        # Read-back phase: reopen and verify persisted data
        fh2 = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        data = fs.read(f"/{fs.file_name}", len(new_content) + 100, 0, fh2)
        assert data == new_content
        fs.release(f"/{fs.file_name}", fh2)

    def test_overwrite_entire_file_roundtrip(self, single_fs):
        """Truncate to 0, write new content, release, reopen, verify."""
        fs, _ = single_fs
        new_content = b"Replaced everything with this new data."

        # Overwrite
        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)
        fs.truncate(f"/{fs.file_name}", 0, fh)
        fs.write(f"/{fs.file_name}", new_content, 0, fh)
        fs.truncate(f"/{fs.file_name}", len(new_content), fh)
        fs.release(f"/{fs.file_name}", fh)

        # Verify
        fh2 = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        data = fs.read(f"/{fs.file_name}", len(new_content) + 100, 0, fh2)
        assert data == new_content
        fs.release(f"/{fs.file_name}", fh2)

    def test_write_release_reopen_large_file_roundtrip(self, large_file_fs):
        """Multi-chunk write spanning boundaries, release, reopen, full read-back."""
        fs, original_content = large_file_fs
        chunk_size = fs.chunk_size

        # Modify data spanning a chunk boundary
        offset = chunk_size - 50
        patch = b"X" * 200  # crosses from chunk 0 into chunk 1

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)
        fs.write(f"/{fs.file_name}", patch, offset, fh)
        fs.release(f"/{fs.file_name}", fh)

        # Build expected content
        expected = bytearray(original_content)
        expected[offset : offset + len(patch)] = patch
        expected = bytes(expected)

        # Reopen and read back full file
        fh2 = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        read_offset = 0
        data = bytearray()
        while read_offset < len(expected):
            chunk = fs.read(f"/{fs.file_name}", chunk_size, read_offset, fh2)
            if not chunk:
                break
            data.extend(chunk)
            read_offset += len(chunk)

        assert bytes(data) == expected
        fs.release(f"/{fs.file_name}", fh2)


class TestSingleFileFSAtomicSave:
    """Tests for the temp→main rename pattern used by Word/Adobe."""

    def test_rename_temp_to_main_commits_content(self, single_fs):
        """Renaming the temp save file over the main file should commit its content."""
        fs, original_content = single_fs
        new_content = b"New content written via temp file atomic save"

        # Create temp and write to it
        temp_fh = fs.create("/~WRD0000.tmp", mode=0o644)
        fs.write("/~WRD0000.tmp", new_content, 0, temp_fh)
        fs._temp_meta["~WRD0000.tmp"]["size"] = len(new_content)

        # Rename temp → main (this calls _write_full_file internally)
        fs.rename("/~WRD0000.tmp", f"/{fs.file_name}")

        # Verify main file now has new content
        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        data = fs.read(f"/{fs.file_name}", len(new_content) + 100, 0, fh)
        assert data == new_content
        fs.release(f"/{fs.file_name}", fh)

        # Temp file should be gone
        entries = fs.readdir("/", fh=0)
        assert "~WRD0000.tmp" not in entries

    def test_rename_main_to_temp_reads_content(self, single_fs):
        """Rename main→temp, verify temp has original content in readdir."""
        fs, original_content = single_fs

        fs.rename(f"/{fs.file_name}", "/~WRL0001.tmp")

        # Temp should exist in readdir
        entries = fs.readdir("/", fh=0)
        assert "~WRL0001.tmp" in entries

        # Temp should contain the original file data
        assert fs._temp_files["~WRL0001.tmp"] == bytearray(original_content)

    def test_full_word_atomic_save_sequence(self, single_fs):
        """Simulate the complete Word atomic save pattern."""
        fs, original_content = single_fs
        new_content = b"Document content after Word save"

        # Step 1: Create temp write file
        temp_fh = fs.create("/~WRD0000.tmp", mode=0o644)

        # Step 2: Write new data to temp
        fs.write("/~WRD0000.tmp", new_content, 0, temp_fh)
        fs._temp_meta["~WRD0000.tmp"]["size"] = len(new_content)

        # Step 3: Rename main → backup temp
        fs.rename(f"/{fs.file_name}", "/~WRL0001.tmp")

        # Step 4: Rename write-temp → main (atomic save)
        fs.rename("/~WRD0000.tmp", f"/{fs.file_name}")

        # Step 5: Delete backup
        fs.unlink("/~WRL0001.tmp")

        # Verify: main has new content
        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        data = fs.read(f"/{fs.file_name}", len(new_content) + 100, 0, fh)
        assert data == new_content
        fs.release(f"/{fs.file_name}", fh)

        # No temp files remain
        entries = fs.readdir("/", fh=0)
        assert "~WRD0000.tmp" not in entries
        assert "~WRL0001.tmp" not in entries

    def test_rename_temp_to_temp(self, single_fs):
        """Rename one temp file to another temp name."""
        fs, _ = single_fs
        data = b"Temp file data"

        temp_fh = fs.create("/source.tmp", mode=0o644)
        fs.write("/source.tmp", data, 0, temp_fh)

        fs.rename("/source.tmp", "/dest.tmp")

        assert "source.tmp" not in fs._temp_files
        assert fs._temp_files["dest.tmp"] == bytearray(data)

    def test_destroy_cleans_up(self, single_fs):
        """Verify destroy cleans up handles and temp files."""
        fs, _ = single_fs

        # Open main file
        # fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        # Create a temp file
        fs.create("/temp.tmp", mode=0o644)

        # Destroy
        fs.destroy("/")

        assert fs.handle_manager.open_handle_count == 0
        assert fs._temp_files == {}
        assert fs._temp_meta == {}
