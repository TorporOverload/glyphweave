"""Integration tests for concurrent file lifecycle operations."""

import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


def _write_bytes_with_retry(path: Path, data: bytes, retries: int = 5, delay: float = 0.1) -> None:
    """Write bytes to path, retrying on PermissionError (Windows AV lock)."""
    for attempt in range(retries):
        try:
            path.write_bytes(data)
            return
        except PermissionError:
            if attempt == retries - 1:
                raise
            time.sleep(delay)


def _add_file_with_retry(service, source: Path, dest_name: str, retries: int = 5, delay: float = 0.15):
    """Call add_file with retries on PermissionError (Windows AV briefly locks new files)."""
    for attempt in range(retries):
        try:
            return service.add_file(source, dest_name=dest_name)
        except PermissionError:
            if attempt == retries - 1:
                raise
            time.sleep(delay)

import pytest

from app.services.vault_files.vault_file_service import VaultFileService


class TestConcurrentFileLifecycle:
    def test_concurrent_add_files(
        self,
        vault_file_service: VaultFileService,
        tmp_path: Path,
    ) -> None:
        """Adding multiple files concurrently should succeed."""
        def add_file(index: int) -> str:
            source = tmp_path / f"source_{index}.txt"
            _write_bytes_with_retry(source, f"Content {index}".encode())
            result = _add_file_with_retry(vault_file_service, source, f"file_{index}.txt")
            return result.file_name

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(add_file, i) for i in range(8)]
            names = [f.result() for f in as_completed(futures)]

        entries = vault_file_service.list_root_entries()
        file_names = sorted(e.name for e in entries if not e.is_folder)
        assert len(file_names) == 8
        assert file_names == sorted(names)

    def test_concurrent_add_deduplication(
        self,
        vault_file_service: VaultFileService,
        tmp_path: Path,
    ) -> None:
        """Concurrent imports of identical content should deduplicate correctly."""
        source = tmp_path / "common.txt"
        source.write_bytes(b"Shared content for deduplication")

        results = []
        errors = []

        def add_file(index: int):
            result = vault_file_service.add_file(
                source, dest_name=f"shared_{index}.txt"
            )
            return result.deduplicated

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(add_file, i) for i in range(4)]
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    errors.append(exc)

        assert errors == []
        assert len(results) == 4
        assert results.count(True) >= 1
        assert results.count(True) + results.count(False) == len(results)

    def test_concurrent_modify_different_files(
        self,
        vault_file_service: VaultFileService,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        """Modifying different files concurrently should work correctly."""
        import app.services.vault_files.vault_file_fallback as fb_mod
        monkeypatch.setattr(fb_mod, "open_with_default_app", lambda _: None)

        for i in range(4):
            source = tmp_path / f"orig_{i}.txt"
            source.write_bytes(f"Original {i}".encode())
            vault_file_service.add_file(source, dest_name=f"target_{i}.txt")

        def modify_file(index: int) -> None:
            entries = vault_file_service.list_root_entries()
            ref = next(e for e in entries if e.name == f"target_{index}.txt")
            open_result = vault_file_service.open_file_by_ref(
                ref.id, launch_in_default_app=False
            )
            _write_bytes_with_retry(open_result.file_path, f"Modified {index}".encode())
            vault_file_service.unmount_unlocked(ref.id)

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(modify_file, i) for i in range(4)]
            for f in as_completed(futures):
                f.result()

        for i in range(4):
            entries = vault_file_service.list_root_entries()
            ref = next(e for e in entries if e.name == f"target_{i}.txt")
            open_result = vault_file_service.open_file_by_ref(
                ref.id, launch_in_default_app=False
            )
            assert open_result.file_path.read_bytes() == f"Modified {i}".encode()
            vault_file_service.unmount_unlocked(ref.id)

    def test_concurrent_open_same_file(
        self,
        vault_file_service: VaultFileService,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        """Opening the same file concurrently should be handled gracefully."""
        import app.services.vault_files.vault_file_fallback as fb_mod
        monkeypatch.setattr(fb_mod, "open_with_default_app", lambda _: None)

        source = tmp_path / "shared.txt"
        source.write_bytes(b"Shared file content")
        vault_file_service.add_file(source, dest_name="shared.txt")
        entries = vault_file_service.list_root_entries()
        ref = next(e for e in entries if e.name == "shared.txt")
        ref_id = ref.id

        errors = []

        expected_errors = []
        other_errors = []

        def open_and_unmount():
            try:
                open_result = vault_file_service.open_file_by_ref(
                    ref_id, launch_in_default_app=False
                )
                time.sleep(0.05)
                vault_file_service.unmount_unlocked(ref_id)
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(open_and_unmount) for _ in range(2)]
            for f in as_completed(futures):
                f.result()

        for e in errors:
            if (isinstance(e, PermissionError) or
                "being used by another process" in str(e) or
                "no longer unlocked" in str(e) or
                "FileNotFoundError" in type(e).__name__):
                expected_errors.append(e)
            else:
                other_errors.append(e)

        assert len(other_errors) == 0, f"Unexpected errors: {other_errors}"

    def test_concurrent_mount_unmount(
        self,
        vault_file_service: VaultFileService,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        """Concurrent mount/unmount operations on different files."""
        import app.services.vault_files.vault_file_fallback as fb_mod
        monkeypatch.setattr(fb_mod, "open_with_default_app", lambda _: None)

        for i in range(4):
            source = tmp_path / f"src_{i}.txt"
            source.write_bytes(f"Content {i}".encode())
            vault_file_service.add_file(source, dest_name=f"file_{i}.txt")

        def cycle_file(index: int) -> str:
            entries = vault_file_service.list_root_entries()
            ref = next(e for e in entries if e.name == f"file_{index}.txt")
            open_result = vault_file_service.open_file_by_ref(
                ref.id, launch_in_default_app=False
            )
            time.sleep(0.01)
            msg = vault_file_service.unmount_unlocked(ref.id)
            return msg

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(cycle_file, i) for i in range(4)]
            results = [f.result() for f in as_completed(futures)]

        assert all("saved" in r.lower() or "no changes" in r.lower() for r in results)

    def test_concurrent_add_and_delete(
        self,
        vault_file_service: VaultFileService,
        tmp_path: Path,
    ) -> None:
        """Adding and deleting files concurrently should not cause errors."""
        errors = []
        start = threading.Event()

        for i in range(4):
            source = tmp_path / f"existing_{i}.txt"
            source.write_bytes(f"Existing {i}".encode())
            vault_file_service.add_file(source, dest_name=f"existing_{i}.txt")

        entries = vault_file_service.list_root_entries()
        existing_names = {f"existing_{i}.txt" for i in range(4)}
        existing_paths = [
            f"/{entry.name}"
            for entry in entries
            if not entry.is_folder and entry.name in existing_names
        ]
        assert sorted(existing_paths) == [f"/existing_{i}.txt" for i in range(4)]

        def add_file(index: int):
            try:
                source = tmp_path / f"to_add_{index}.txt"
                _write_bytes_with_retry(source, f"To be added {index}".encode())
                start.wait()
                result = _add_file_with_retry(vault_file_service, source, f"added_{index}.txt")
                return result.file_name
            except Exception as e:
                errors.append(e)
                return None

        def delete_file(virtual_path: str):
            try:
                start.wait()
                deleted_count = vault_file_service.delete_entries([virtual_path])
                return deleted_count
            except Exception as e:
                errors.append(e)
                return None

        with ThreadPoolExecutor(max_workers=4) as executor:
            add_futures = [executor.submit(add_file, i) for i in range(4)]
            delete_futures = [
                executor.submit(delete_file, virtual_path)
                for virtual_path in existing_paths
            ]
            start.set()
            added_names = [f.result() for f in as_completed(add_futures)]
            deleted_counts = [f.result() for f in as_completed(delete_futures)]

        assert errors == []
        assert sorted(added_names) == [f"added_{i}.txt" for i in range(4)]
        assert deleted_counts == [1, 1, 1, 1]

        remaining_names = sorted(
            entry.name
            for entry in vault_file_service.list_root_entries()
            if not entry.is_folder
        )
        assert remaining_names == [f"added_{i}.txt" for i in range(4)]

    def test_concurrent_add_modify_delete(
        self,
        vault_file_service: VaultFileService,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        """Full concurrent lifecycle: add, modify, unmount, delete different files."""
        import app.services.vault_files.vault_file_fallback as fb_mod
        monkeypatch.setattr(fb_mod, "open_with_default_app", lambda _: None)

        for i in range(4):
            source = tmp_path / f"base_{i}.txt"
            source.write_bytes(f"Base {i}".encode())
            vault_file_service.add_file(source, dest_name=f"lifecycle_{i}.txt")

        errors = []

        def cycle_file(index: int):
            try:
                entries = vault_file_service.list_root_entries()
                ref = next(e for e in entries if e.name == f"lifecycle_{index}.txt")
                open_result = vault_file_service.open_file_by_ref(
                    ref.id, launch_in_default_app=False
                )
                _write_bytes_with_retry(open_result.file_path, f"Updated {index}".encode())
                vault_file_service.unmount_unlocked(ref.id)
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(cycle_file, i) for i in range(4)]
            for f in as_completed(futures):
                f.result()

        assert len(errors) == 0
        for i in range(4):
            entries = vault_file_service.list_root_entries()
            ref = next(e for e in entries if e.name == f"lifecycle_{i}.txt")
            open_result = vault_file_service.open_file_by_ref(
                ref.id, launch_in_default_app=False
            )
            assert open_result.file_path.read_bytes() == f"Updated {i}".encode()
            vault_file_service.unmount_unlocked(ref.id)
