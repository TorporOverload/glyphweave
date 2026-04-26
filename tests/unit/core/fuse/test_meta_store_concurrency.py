"""Unit tests for MetaStore concurrent access scenarios."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

import pytest

from app.infrastructure.fuse.meta_store import MetaStore


class TestConcurrentFileCreation:
    def test_concurrent_file_creation_in_different_directories(self):
        store = MetaStore()
        store.create_directory("/dir1")
        store.create_directory("/dir2")
        store.create_directory("/dir3")

        results = []
        errors = []

        def create_file(dir_name: str, index: int):
            try:
                meta = store.create_file(f"/{dir_name}/file_{index}.txt")
                return ("success", meta.file_id, f"/{dir_name}/file_{index}.txt")
            except Exception as e:
                return ("error", str(e), f"/{dir_name}/file_{index}.txt")

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = []
            for i in range(10):
                futures.append(executor.submit(create_file, "dir1", i))
                futures.append(executor.submit(create_file, "dir2", i))
                futures.append(executor.submit(create_file, "dir3", i))

            for future in as_completed(futures):
                result = future.result()
                if result[0] == "error":
                    errors.append(result)
                else:
                    results.append(result)

        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 30

        for result in results:
            path = result[2]
            assert store.is_file(path)

        assert len(store.list_directory("/dir1")) == 10
        assert len(store.list_directory("/dir2")) == 10
        assert len(store.list_directory("/dir3")) == 10

    def test_concurrent_file_creation_same_directory(self):
        store = MetaStore()
        store.create_directory("/shared")

        results: List = []
        lock = threading.Lock()

        def create_file(index: int):
            try:
                meta = store.create_file(f"/shared/file_{index}.txt")
                with lock:
                    results.append(("success", meta.file_id))
                return True
            except Exception as e:
                with lock:
                    results.append(("error", str(e)))
                return False

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(create_file, i) for i in range(20)]
            for future in as_completed(futures):
                future.result()

        successful = [r for r in results if r[0] == "success"]
        assert len(successful) == 20
        assert len(store.list_directory("/shared")) == 20


class TestConcurrentRename:
    def test_concurrent_rename_different_files(self):
        store = MetaStore()
        for i in range(10):
            store.create_file(f"/file_{i}.txt")

        results = []
        lock = threading.Lock()

        def rename_file(index: int):
            try:
                store.rename(f"/file_{index}.txt", f"/renamed_{index}.txt")
                with lock:
                    results.append("success")
                return True
            except Exception as e:
                with lock:
                    results.append(f"error: {e}")
                return False

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(rename_file, i) for i in range(10)]
            for future in as_completed(futures):
                future.result()

        errors = [r for r in results if not r == "success"]
        assert len(errors) == 0, f"Errors: {errors}"

        for i in range(10):
            assert not store.path_exists(f"/file_{i}.txt")
            assert store.is_file(f"/renamed_{i}.txt")

    def test_concurrent_rename_to_same_target(self):
        store = MetaStore()
        store.create_file("/source1.txt")
        store.create_file("/source2.txt")

        results = []
        lock = threading.Lock()

        def rename_to_target(source: str):
            try:
                store.rename(source, "/target.txt")
                with lock:
                    results.append("success")
            except Exception as e:
                with lock:
                    results.append(f"error: {e}")

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(rename_to_target, "/source1.txt"),
                executor.submit(rename_to_target, "/source2.txt")
            ]
            for future in as_completed(futures):
                future.result()

        assert store.path_exists("/target.txt")
        successes = [r for r in results if r == "success"]
        assert len(successes) == 2 or len(successes) == 1


class TestConcurrentDirectoryListing:
    def test_list_during_file_creation(self):
        store = MetaStore()
        store.create_directory("/watched")

        listing_results: List = []
        listing_lock = threading.Lock()
        stop_listing = threading.Event()

        def list_directory():
            count = 0
            while not stop_listing.is_set() and count < 100:
                try:
                    entries = store.list_directory("/watched")
                    with listing_lock:
                        listing_results.append(len(entries))
                except Exception:
                    pass
                time.sleep(0.001)
                count += 1

        def create_files():
            for i in range(50):
                store.create_file(f"/watched/file_{i}.txt")
                time.sleep(0.001)

        listing_thread = threading.Thread(target=list_directory)
        listing_thread.start()

        create_files()

        stop_listing.set()
        listing_thread.join()

        assert len(store.list_directory("/watched")) == 50
        assert max(listing_results) >= 0

    def test_list_during_rename(self):
        store = MetaStore()
        store.create_directory("/dir1")
        store.create_directory("/dir2")
        for i in range(20):
            store.create_file(f"/dir1/file_{i}.txt")

        listing_results: List = []
        listing_lock = threading.Lock()
        stop_listing = threading.Event()

        def list_directories():
            while not stop_listing.is_set():
                try:
                    with listing_lock:
                        listing_results.append((
                            len(store.list_directory("/dir1")),
                            len(store.list_directory("/dir2"))
                        ))
                except Exception:
                    pass

        def rename_files():
            for i in range(20):
                store.rename(f"/dir1/file_{i}.txt", f"/dir2/file_{i}.txt")
                time.sleep(0.001)

        listing_thread = threading.Thread(target=list_directories)
        listing_thread.start()

        rename_files()

        stop_listing.set()
        listing_thread.join()

        assert len(store.list_directory("/dir1")) == 0
        assert len(store.list_directory("/dir2")) == 20


class TestMetadataUpdateThreadSafety:
    def test_concurrent_metadata_updates(self):
        store = MetaStore()
        metas = []
        for i in range(10):
            meta = store.create_file(f"/file_{i}.txt")
            metas.append(meta)

        update_count = [0]
        lock = threading.Lock()

        def update_metadata(meta, index):
            try:
                for j in range(10):
                    meta.plaintext_size = (index + 1) * (j + 1)
                    store.update_metadata(meta.file_id, meta)
                    with lock:
                        update_count[0] += 1
            except Exception as e:
                pass

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(update_metadata, meta, i)
                for i, meta in enumerate(metas)
            ]
            for future in as_completed(futures):
                future.result()

        assert update_count[0] == 100
        for i, meta in enumerate(metas):
            current = store.get_metadata_by_id(meta.file_id)
            assert current.plaintext_size == (i + 1) * 10

    def test_concurrent_reads_and_updates(self):
        store = MetaStore()
        meta = store.create_file("/shared.txt")

        reads = []
        writes = []
        reads_lock = threading.Lock()
        writes_lock = threading.Lock()

        def reader():
            for _ in range(50):
                try:
                    result = store.get_metadata("/shared.txt")
                    with reads_lock:
                        reads.append(result.plaintext_size if result else None)
                except Exception:
                    pass

        def writer():
            for i in range(50):
                meta.plaintext_size = i
                store.update_metadata(meta.file_id, meta)
                with writes_lock:
                    writes.append(i)

        with ThreadPoolExecutor(max_workers=20) as executor:
            reader_futures = [executor.submit(reader) for _ in range(5)]
            writer_futures = [executor.submit(writer) for _ in range(5)]

            for future in as_completed(reader_futures + writer_futures):
                future.result()

        assert len(reads) > 0
        assert len(writes) == 250


class TestConcurrentDelete:
    def test_concurrent_delete_different_files(self):
        store = MetaStore()
        for i in range(20):
            store.create_file(f"/file_{i}.txt")

        results = []

        def delete_file(index: int):
            try:
                file_id = store.delete_file(f"/file_{index}.txt")
                results.append(file_id is not None)
            except Exception:
                results.append(False)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(delete_file, i) for i in range(20)]
            for future in as_completed(futures):
                future.result()

        assert all(results)
        assert len(store.list_directory("/")) == 0

    def test_concurrent_delete_and_create_same_path(self):
        store = MetaStore()
        store.create_directory("/dir")
        errors = []

        def delete_path():
            try:
                store.delete_file("/dir/file.txt")
            except FileNotFoundError:
                pass
            except Exception as e:
                errors.append(str(e))

        def create_path():
            try:
                store.create_file("/dir/file.txt")
            except FileExistsError:
                pass
            except Exception as e:
                errors.append(str(e))

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for _ in range(10):
                futures.append(executor.submit(delete_path))
                futures.append(executor.submit(create_path))

            for future in as_completed(futures):
                future.result()

        assert len(errors) == 0


class TestConcurrentDirectoryOperations:
    def test_concurrent_directory_creation_different_paths(self):
        store = MetaStore()

        results = []

        def create_dir(name: str):
            try:
                store.create_directory(f"/{name}")
                results.append(True)
            except Exception:
                results.append(False)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(create_dir, f"dir_{i}") for i in range(20)]
            for future in as_completed(futures):
                future.result()

        assert len([r for r in results if r]) == 20
        assert len(store.list_directory("/")) == 20

    def test_concurrent_mkdir_and_list(self):
        store = MetaStore()
        listings = []
        lock = threading.Lock()

        def create_dir(index: int):
            try:
                store.create_directory(f"/new_dir_{index}")
            except Exception:
                pass

        def list_dirs():
            for _ in range(50):
                try:
                    with lock:
                        listings.append(len(store.list_directory("/")))
                except Exception:
                    pass

        with ThreadPoolExecutor(max_workers=15) as executor:
            dir_futures = [executor.submit(create_dir, i) for i in range(30)]
            list_futures = [executor.submit(list_dirs) for _ in range(3)]

            for future in as_completed(dir_futures + list_futures):
                future.result()

        assert len(store.list_directory("/")) == 30
