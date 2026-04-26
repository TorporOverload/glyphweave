"""
Stress tests for SingleFileFS - single-file FUSE filesystem.

These tests exercise stress scenarios including large files, concurrent
operations, and atomic save patterns with large files.
"""

import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pytest


class TestSingleFileFSStressLargeFile:
    """Stress tests for very large file operations."""

    def test_very_large_file_read_full(self, large_file_fs):
        """Test reading entire large file multiple times."""
        fs, original_content = large_file_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)

        chunk_size = 64 * 1024
        for _ in range(3):
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

    def test_very_large_file_write_and_read_back(self, large_file_fs):
        """Test writing large amount of data and reading it back."""
        fs, original_content = large_file_fs
        chunk_size = fs.chunk_size

        new_content = os.urandom(len(original_content))

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)
        written = fs.write(f"/{fs.file_name}", new_content, 0, fh)
        assert written == len(new_content)
        fs.release(f"/{fs.file_name}", fh)

        fh2 = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        offset = 0
        data = bytearray()
        while offset < len(new_content):
            chunk = fs.read(f"/{fs.file_name}", chunk_size, offset, fh2)
            if not chunk:
                break
            data.extend(chunk)
            offset += len(chunk)
        assert bytes(data) == new_content
        fs.release(f"/{fs.file_name}", fh2)

    def test_multi_chunk_boundary_stress(self, large_file_fs):
        """Stress test across multiple chunk boundaries."""
        fs, original_content = large_file_fs
        chunk_size = fs.chunk_size

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)

        patch_size = chunk_size // 2
        num_patches = (len(original_content) // chunk_size) + 2

        for i in range(num_patches):
            offset = i * chunk_size
            if offset >= len(original_content):
                break
            patch = bytes([i % 256]) * patch_size
            remaining = len(original_content) - offset
            if remaining <= 0:
                break
            actual_patch = patch[: min(patch_size, remaining)]

            written = fs.write(f"/{fs.file_name}", actual_patch, offset, fh)
            assert written == len(actual_patch)

        fs.release(f"/{fs.file_name}", fh)

        fh2 = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        verify_offset = 0
        verify_data = bytearray()
        while verify_offset < len(original_content):
            chunk = fs.read(f"/{fs.file_name}", chunk_size, verify_offset, fh2)
            if not chunk:
                break
            verify_data.extend(chunk)
            verify_offset += len(chunk)

        expected = bytearray(original_content)
        for i in range(num_patches):
            offset = i * chunk_size
            if offset >= len(expected):
                break
            patch = bytes([i % 256]) * patch_size
            remaining = len(original_content) - offset
            if remaining <= 0:
                break
            actual_patch = patch[: min(patch_size, remaining)]
            end_offset = min(offset + len(actual_patch), len(expected))
            expected[offset:end_offset] = actual_patch[: end_offset - offset]

        assert bytes(verify_data) == bytes(expected)
        fs.release(f"/{fs.file_name}", fh2)


class TestSingleFileFSConcurrentHandles:
    """Tests for multiple concurrent file handles."""

    def test_concurrent_reads_same_handle(self, single_fs):
        """Test concurrent reads using the same file handle."""
        fs, original_content = single_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)

        results = []
        errors = []

        def read_chunk(offset, size):
            try:
                data = fs.read(f"/{fs.file_name}", size, offset, fh)
                return (offset, data)
            except Exception as e:
                return (offset, e)

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for i in range(10):
                offset = (i * 100) % len(original_content)
                size = min(100, len(original_content) - offset)
                futures.append(executor.submit(read_chunk, offset, size))

            for future in as_completed(futures):
                result = future.result()
                if isinstance(result[1], Exception):
                    errors.append(result)
                else:
                    results.append(result)

        assert len(errors) == 0, f"Errors occurred: {errors}"

        for offset, data in results:
            expected = original_content[offset : offset + len(data)]
            assert data == expected

        fs.release(f"/{fs.file_name}", fh)

    def test_concurrent_reads_different_handles(self, single_fs):
        """Test concurrent reads using different file handles."""
        fs, original_content = single_fs

        results = []
        errors = []

        def open_read_close(offset, size):
            try:
                fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
                data = fs.read(f"/{fs.file_name}", size, offset, fh)
                fs.release(f"/{fs.file_name}", fh)
                return (offset, data)
            except Exception as e:
                return (offset, e)

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for i in range(20):
                offset = (i * 50) % len(original_content)
                size = min(50, len(original_content) - offset)
                futures.append(executor.submit(open_read_close, offset, size))

            for future in as_completed(futures):
                result = future.result()
                if isinstance(result[1], Exception):
                    errors.append(result)
                else:
                    results.append(result)

        assert len(errors) == 0, f"Errors occurred: {errors}"

        for offset, data in results:
            expected = original_content[offset : offset + len(data)]
            assert data == expected

    def test_multiple_writers_sequential(self, single_fs):
        """Test multiple sequential writes from different offsets."""
        fs, original_content = single_fs

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)

        offsets_and_data = [
            (0, b"FIRST"),
            (len(original_content) - 10, b"SECOND"),
            (len(original_content) // 2, b"MIDDLE"),
        ]

        for offset, data in offsets_and_data:
            written = fs.write(f"/{fs.file_name}", data, offset, fh)
            assert written == len(data)

        fs.release(f"/{fs.file_name}", fh)

        fh2 = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        for offset, data in offsets_and_data:
            read_data = fs.read(f"/{fs.file_name}", len(data), offset, fh2)
            assert read_data == data
        fs.release(f"/{fs.file_name}", fh2)


class TestSingleFileFSAtomicSaveStress:
    """Stress tests for atomic save pattern with large files."""

    def test_atomic_save_large_file(self, large_file_fs):
        """Test atomic save pattern with large file content."""
        fs, original_content = large_file_fs
        new_content = os.urandom(len(original_content))

        temp_fh = fs.create("/~WRD0000.tmp", mode=0o644)

        chunk_size = fs.chunk_size
        offset = 0
        while offset < len(new_content):
            chunk = new_content[offset : offset + chunk_size]
            written = fs.write("/~WRD0000.tmp", bytes(chunk), offset, temp_fh)
            assert written == len(chunk)
            offset += len(chunk)

        fs._temp_meta["~WRD0000.tmp"]["size"] = len(new_content)

        fs.rename(f"/{fs.file_name}", "/~WRL0001.tmp")
        fs.rename("/~WRD0000.tmp", f"/{fs.file_name}")

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        read_offset = 0
        data = bytearray()
        while read_offset < len(new_content):
            chunk = fs.read(f"/{fs.file_name}", chunk_size, read_offset, fh)
            if not chunk:
                break
            data.extend(chunk)
            read_offset += len(chunk)

        assert bytes(data) == new_content
        fs.release(f"/{fs.file_name}", fh)

        entries = fs.readdir("/", fh=0)
        assert "~WRD0000.tmp" not in entries
        assert "~WRL0001.tmp" in entries

        fs.unlink("/~WRL0001.tmp")

        entries = fs.readdir("/", fh=0)
        assert "~WRL0001.tmp" not in entries

    def test_atomic_save_cross_chunk_boundary(self, large_file_fs):
        """Test atomic save with data spanning chunk boundaries."""
        fs, original_content = large_file_fs
        chunk_size = fs.chunk_size

        new_size = len(original_content) + chunk_size
        new_content = os.urandom(new_size)

        temp_fh = fs.create("/~WRD0000.tmp", mode=0o644)

        written_total = 0
        offset = 0
        while offset < len(new_content):
            chunk = new_content[offset : offset + chunk_size]
            written = fs.write("/~WRD0000.tmp", bytes(chunk), offset, temp_fh)
            assert written == len(chunk)
            written_total += written
            offset += len(chunk)

        fs._temp_meta["~WRD0000.tmp"]["size"] = len(new_content)

        fs.rename(f"/{fs.file_name}", "/~WRL0001.tmp")
        fs.rename("/~WRD0000.tmp", f"/{fs.file_name}")

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        attrs = fs.getattr(f"/{fs.file_name}", fh)
        assert attrs["st_size"] == len(new_content)

        read_offset = chunk_size - 100
        size = 300
        if read_offset + size <= len(new_content):
            data = fs.read(f"/{fs.file_name}", size, read_offset, fh)
            assert data == new_content[read_offset : read_offset + size]

        fs.release(f"/{fs.file_name}", fh)

        fs.unlink("/~WRL0001.tmp")


class TestSingleFileFSCrossChunkStress:
    """Stress tests for cross-chunk boundary operations."""

    def test_write_spanning_multiple_chunks(self, large_file_fs):
        """Test writing data that spans multiple chunks."""
        fs, original_content = large_file_fs
        chunk_size = fs.chunk_size

        offset = chunk_size - 100
        length = chunk_size * 3
        new_data = b"Y" * length

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)
        written = fs.write(f"/{fs.file_name}", new_data, offset, fh)
        assert written == length
        fs.release(f"/{fs.file_name}", fh)

        fh2 = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        read_data = fs.read(f"/{fs.file_name}", length, offset, fh2)
        assert read_data == new_data
        fs.release(f"/{fs.file_name}", fh2)

    def test_read_at_chunk_boundaries(self, large_file_fs):
        """Test reading at exact chunk boundaries."""
        fs, original_content = large_file_fs
        chunk_size = fs.chunk_size

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)

        boundaries = [
            chunk_size - 1,
            chunk_size,
            chunk_size + 1,
            chunk_size * 2 - 1,
            chunk_size * 2,
            chunk_size * 2 + 1,
        ]

        for boundary in boundaries:
            if boundary >= len(original_content):
                continue
            size = min(100, len(original_content) - boundary)
            data = fs.read(f"/{fs.file_name}", size, boundary, fh)
            assert data == original_content[boundary : boundary + size]

        fs.release(f"/{fs.file_name}", fh)

    def test_write_at_chunk_boundaries(self, large_file_fs):
        """Test writing at exact chunk boundaries."""
        fs, original_content = large_file_fs
        chunk_size = fs.chunk_size

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)

        boundaries = [
            (chunk_size - 50, 50),
            (chunk_size, 50),
            (chunk_size + 50, 50),
        ]

        for i, (boundary, size) in enumerate(boundaries):
            if boundary >= len(original_content):
                continue
            write_data = bytes([i + 1]) * size
            written = fs.write(f"/{fs.file_name}", write_data, boundary, fh)
            assert written == len(write_data)

        fs.release(f"/{fs.file_name}", fh)

        fh2 = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        for i, (boundary, size) in enumerate(boundaries):
            if boundary >= len(original_content):
                continue
            read_data = fs.read(f"/{fs.file_name}", size, boundary, fh2)
            assert read_data == bytes([i + 1]) * size
        fs.release(f"/{fs.file_name}", fh2)

    def test_overlapping_chunk_modifications(self, large_file_fs):
        """Test multiple overlapping modifications to same chunks - last write wins."""
        fs, original_content = large_file_fs
        chunk_size = fs.chunk_size

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)

        fs.write(f"/{fs.file_name}", b"A" * 50, 0, fh)
        fs.write(f"/{fs.file_name}", b"B" * 50, 25, fh)
        fs.write(f"/{fs.file_name}", b"C" * 50, 50, fh)

        fs.release(f"/{fs.file_name}", fh)

        fh2 = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        first_25 = fs.read(f"/{fs.file_name}", 25, 0, fh2)
        assert first_25 == b"A" * 25

        next_25 = fs.read(f"/{fs.file_name}", 25, 25, fh2)
        assert next_25 == b"B" * 25

        next_25 = fs.read(f"/{fs.file_name}", 25, 50, fh2)
        assert next_25 == b"C" * 25

        next_25 = fs.read(f"/{fs.file_name}", 25, 75, fh2)
        assert next_25 == b"C" * 25

        fs.release(f"/{fs.file_name}", fh2)


class TestSingleFileFSSequentialOperations:
    """Stress tests for sequential operations on same file."""

    def test_repeated_open_write_release_cycle(self, single_fs):
        """Test repeated open-write-release cycles with non-overlapping writes."""
        fs, original_content = single_fs

        offsets = [0, 100, 200, 300, 400, 500, 600, 700, 800, 900]
        for iteration in range(10):
            fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)
            write_data = bytes([iteration]) * 50
            written = fs.write(f"/{fs.file_name}", write_data, offsets[iteration], fh)
            assert written == len(write_data)
            fs.release(f"/{fs.file_name}", fh)

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        for iteration in range(10):
            offset = offsets[iteration]
            read_data = fs.read(f"/{fs.file_name}", 50, offset, fh)
            assert read_data == bytes([iteration]) * 50
        fs.release(f"/{fs.file_name}", fh)

    def test_truncate_write_read_single_iteration(self, large_file_fs):
        """Test truncate-write-read cycle once."""
        fs, original_content = large_file_fs
        chunk_size = fs.chunk_size

        fh = fs.open(f"/{fs.file_name}", flags=os.O_RDWR)
        new_size = chunk_size * 2
        fs.truncate(f"/{fs.file_name}", new_size, fh)

        attrs = fs.getattr(f"/{fs.file_name}", fh)
        assert attrs["st_size"] == new_size

        write_data = os.urandom(100)
        fs.write(f"/{fs.file_name}", write_data, 0, fh)

        fs.release(f"/{fs.file_name}", fh)

        fh2 = fs.open(f"/{fs.file_name}", flags=os.O_RDONLY)
        attrs2 = fs.getattr(f"/{fs.file_name}", fh2)
        assert attrs2["st_size"] == new_size

        read_data = fs.read(f"/{fs.file_name}", 100, 0, fh2)
        assert read_data == write_data

        fs.release(f"/{fs.file_name}", fh2)
