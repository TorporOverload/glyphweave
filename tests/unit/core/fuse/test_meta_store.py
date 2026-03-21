"""Unit tests for MetaStore - in-memory filesystem metadata tracker."""

import pytest

from app.core.fuse.meta_store import MetaStore


class TestMetaStoreInit:
    def test_initial_state_has_root_directory(self):
        store = MetaStore()
        assert store.is_directory("/")
        assert store.list_directory("/") == []

    def test_root_is_not_a_file(self):
        store = MetaStore()
        assert not store.is_file("/")
        assert store.path_exists("/")


class TestNormalizePath:
    def test_adds_leading_slash(self):
        store = MetaStore()
        assert store.normalize_path("foo") == "/foo"

    def test_strips_trailing_slash(self):
        store = MetaStore()
        assert store.normalize_path("/foo/") == "/foo"

    def test_root_stays_root(self):
        store = MetaStore()
        assert store.normalize_path("/") == "/"

    def test_nested_path(self):
        store = MetaStore()
        assert store.normalize_path("/a/b/c") == "/a/b/c"


class TestGetParentAndName:
    def test_root(self):
        store = MetaStore()
        assert store.get_parent_and_name("/") == ("/", "")

    def test_file_in_root(self):
        store = MetaStore()
        assert store.get_parent_and_name("/file.txt") == ("/", "file.txt")

    def test_nested_file(self):
        store = MetaStore()
        assert store.get_parent_and_name("/dir/file.txt") == ("/dir", "file.txt")


class TestCreateFile:
    def test_create_in_root(self):
        store = MetaStore()
        meta = store.create_file("/test.txt")

        assert meta.file_id is not None
        assert len(meta.file_id) == 32  # hex of 16 bytes
        assert meta.original_name == "test.txt"
        assert meta.plaintext_size == 0
        assert store.path_exists("/test.txt")
        assert store.is_file("/test.txt")
        assert not store.is_directory("/test.txt")
        assert "test.txt" in store.list_directory("/")

    def test_custom_original_name(self):
        store = MetaStore()
        meta = store.create_file("/test.txt", original_name="custom.txt")
        assert meta.original_name == "custom.txt"

    def test_defaults_name_from_path(self):
        store = MetaStore()
        meta = store.create_file("/report.pdf")
        assert meta.original_name == "report.pdf"

    def test_create_in_subdirectory(self):
        store = MetaStore()
        store.create_directory("/docs")
        meta = store.create_file("/docs/report.txt")

        assert store.is_file("/docs/report.txt")
        assert "report.txt" in store.list_directory("/docs")

    def test_nonexistent_parent_raises(self):
        store = MetaStore()
        with pytest.raises(FileNotFoundError):
            store.create_file("/nodir/file.txt")

    def test_duplicate_raises(self):
        store = MetaStore()
        store.create_file("/test.txt")
        with pytest.raises(FileExistsError):
            store.create_file("/test.txt")


class TestCreateDirectory:
    def test_create_in_root(self):
        store = MetaStore()
        store.create_directory("/subdir")

        assert store.is_directory("/subdir")
        assert not store.is_file("/subdir")
        assert "subdir" in store.list_directory("/")
        assert store.list_directory("/subdir") == []

    def test_create_nested(self):
        store = MetaStore()
        store.create_directory("/a")
        store.create_directory("/a/b")

        assert store.is_directory("/a/b")
        assert "b" in store.list_directory("/a")

    def test_missing_parent_raises(self):
        store = MetaStore()
        with pytest.raises(FileNotFoundError):
            store.create_directory("/a/b/c")

    def test_duplicate_raises(self):
        store = MetaStore()
        store.create_directory("/subdir")
        with pytest.raises(FileExistsError):
            store.create_directory("/subdir")


class TestGetFileId:
    def test_returns_id(self):
        store = MetaStore()
        meta = store.create_file("/test.txt")
        assert store.get_file_id("/test.txt") == meta.file_id

    def test_nonexistent_returns_none(self):
        store = MetaStore()
        assert store.get_file_id("/nope") is None

    def test_directory_returns_none(self):
        store = MetaStore()
        store.create_directory("/subdir")
        assert store.get_file_id("/subdir") is None


class TestGetMetadata:
    def test_returns_metadata(self):
        store = MetaStore()
        created = store.create_file("/test.txt")
        fetched = store.get_metadata("/test.txt")
        assert fetched is created

    def test_nonexistent_returns_none(self):
        store = MetaStore()
        assert store.get_metadata("/nope") is None

    def test_get_by_id(self):
        store = MetaStore()
        created = store.create_file("/test.txt")
        fetched = store.get_metadata_by_id(created.file_id)
        assert fetched is created

    def test_get_by_id_nonexistent(self):
        store = MetaStore()
        assert store.get_metadata_by_id("nonexistent") is None


class TestUpdateMetadata:
    def test_update_plaintext_size(self):
        store = MetaStore()
        meta = store.create_file("/test.txt")
        meta.plaintext_size = 1024
        store.update_metadata(meta.file_id, meta)

        fetched = store.get_metadata("/test.txt")
        assert fetched.plaintext_size == 1024

    def test_update_nonexistent_is_noop(self):
        store = MetaStore()
        from app.core.fuse.types import FileMeta

        meta = FileMeta(file_id="fake", original_name="f.txt", plaintext_size=0)
        store.update_metadata("fake", meta)  # should not raise


class TestDeleteFile:
    def test_delete_removes_from_listing(self):
        store = MetaStore()
        meta = store.create_file("/test.txt")
        file_id = store.delete_file("/test.txt")

        assert file_id == meta.file_id
        assert not store.path_exists("/test.txt")
        assert "test.txt" not in store.list_directory("/")

    def test_delete_nonexistent_returns_none(self):
        store = MetaStore()
        assert store.delete_file("/nope") is None

    def test_delete_from_subdirectory(self):
        store = MetaStore()
        store.create_directory("/docs")
        store.create_file("/docs/file.txt")
        store.delete_file("/docs/file.txt")

        assert not store.path_exists("/docs/file.txt")
        assert "file.txt" not in store.list_directory("/docs")


class TestDeleteDirectory:
    def test_delete_empty_directory(self):
        store = MetaStore()
        store.create_directory("/subdir")
        store.delete_directory("/subdir")

        assert not store.path_exists("/subdir")
        assert "subdir" not in store.list_directory("/")

    def test_delete_root_raises(self):
        store = MetaStore()
        with pytest.raises(PermissionError):
            store.delete_directory("/")

    def test_delete_nonempty_raises(self):
        store = MetaStore()
        store.create_directory("/dir")
        store.create_file("/dir/file.txt")
        with pytest.raises(OSError):
            store.delete_directory("/dir")

    def test_delete_nonexistent_raises(self):
        store = MetaStore()
        with pytest.raises(FileNotFoundError):
            store.delete_directory("/nosuchdir")


class TestListDirectory:
    def test_list_root_with_entries(self):
        store = MetaStore()
        store.create_file("/a.txt")
        store.create_file("/b.txt")
        store.create_directory("/docs")

        entries = store.list_directory("/")
        assert set(entries) == {"a.txt", "b.txt", "docs"}

    def test_list_file_raises(self):
        store = MetaStore()
        store.create_file("/file.txt")
        with pytest.raises(NotADirectoryError):
            store.list_directory("/file.txt")

    def test_list_nonexistent_raises(self):
        store = MetaStore()
        with pytest.raises(NotADirectoryError):
            store.list_directory("/nope")


class TestRename:
    def test_rename_file(self):
        store = MetaStore()
        store.create_file("/old.txt")
        store.rename("/old.txt", "/new.txt")

        assert not store.path_exists("/old.txt")
        assert store.is_file("/new.txt")
        meta = store.get_metadata("/new.txt")
        assert meta.original_name == "new.txt"

    def test_rename_file_to_subdirectory(self):
        store = MetaStore()
        store.create_directory("/dir")
        store.create_file("/file.txt")
        store.rename("/file.txt", "/dir/file.txt")

        assert not store.path_exists("/file.txt")
        assert store.is_file("/dir/file.txt")
        assert "file.txt" not in store.list_directory("/")
        assert "file.txt" in store.list_directory("/dir")

    def test_rename_directory_moves_children(self):
        store = MetaStore()
        store.create_directory("/a")
        store.create_file("/a/f.txt")
        store.rename("/a", "/b")

        assert not store.path_exists("/a")
        assert not store.path_exists("/a/f.txt")
        assert store.is_directory("/b")
        assert store.is_file("/b/f.txt")

    def test_rename_nonexistent_raises(self):
        store = MetaStore()
        with pytest.raises(FileNotFoundError):
            store.rename("/nope", "/target")

    def test_rename_to_nonexistent_parent_raises(self):
        store = MetaStore()
        store.create_file("/file.txt")
        with pytest.raises(FileNotFoundError):
            store.rename("/file.txt", "/nodir/file.txt")

    def test_rename_preserves_file_id(self):
        store = MetaStore()
        meta = store.create_file("/old.txt")
        original_id = meta.file_id
        store.rename("/old.txt", "/new.txt")

        assert store.get_file_id("/new.txt") == original_id
