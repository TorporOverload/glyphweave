import secrets
import stat
from typing import Dict, List, Optional, Tuple

from app.core.fuse.types import FileMeta
from app.utils.logging import logger


class MetaStore:
    """In-memory metadata store for the FUSE filesystem."""

    def __init__(self):
        self._path_to_id: Dict[str, str] = {}
        self._files: Dict[str, FileMeta] = {}
        self._directories: Dict[str, set] = {"/": set()}

    def normalize_path(self, path: str) -> str:
        """Ensure path starts with a slash and has no trailing slash (except for
        root)."""
        if not path.startswith("/"):
            path = "/" + path
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        return path

    def get_parent_and_name(self, path: str) -> Tuple[str, str]:
        """Split a path into its parent directory path and the final filename
        component."""
        path = self.normalize_path(path)
        if path == "/":
            return "/", ""
        parts = path.rsplit("/", 1)
        parent = parts[0] if parts[0] else "/"
        name = parts[1]
        return parent, name

    def path_exists(self, path: str) -> bool:
        """Return True if path refers to either a known file or a known directory."""
        path = self.normalize_path(path)
        return path in self._path_to_id or path in self._directories

    def is_directory(self, path: str) -> bool:
        """Return True if path is a registered directory."""
        path = self.normalize_path(path)
        return path in self._directories

    def is_file(self, path: str) -> bool:
        """Return True if path is a registered file."""
        path = self.normalize_path(path)
        return path in self._path_to_id

    def create_file(
        self,
        path: str,
        original_name: Optional[str] = None,
        mode: int = stat.S_IFREG | 0o644,
    ) -> FileMeta:
        """Create a new file entry at path and return its FileMeta."""
        path = self.normalize_path(path)
        parent, name = self.get_parent_and_name(path)
        if not self.is_directory(parent):
            raise FileNotFoundError(f"Parent directory does not exist: {parent}")
        if self.path_exists(path):
            raise FileExistsError(f"Path already exists: {path}")
        file_id = secrets.token_hex(16)
        metadata = FileMeta(
            file_id=file_id,
            original_name=original_name or name,
            plaintext_size=0,
            mode=mode,
        )
        self._path_to_id[path] = file_id
        self._files[file_id] = metadata
        self._directories[parent].add(name)
        logger.debug(f"Created file: {path} -> {file_id}")
        return metadata

    def create_directory(self, path: str, mode: int = stat.S_IFDIR | 0o755) -> None:
        """Register a new directory at path, raising errors for missing parent or
        duplicate."""
        path = self.normalize_path(path)
        parent, name = self.get_parent_and_name(path)
        if path != "/" and not self.is_directory(parent):
            raise FileNotFoundError(f"Parent directory does not exist: {parent}")
        if self.path_exists(path):
            raise FileExistsError(f"Path already exists: {path}")
        self._directories[path] = set()
        if parent in self._directories:
            self._directories[parent].add(name)
        logger.debug(f"Created directory: {path}")

    def get_file_id(self, path: str) -> Optional[str]:
        """Return the file_id for a path, or None if the path is not a registered
        file."""
        path = self.normalize_path(path)
        return self._path_to_id.get(path)

    def get_metadata(self, path: str) -> Optional[FileMeta]:
        """Return FileMeta for a path, or None if the path is not found."""
        file_id = self.get_file_id(path)
        if file_id:
            return self._files.get(file_id)
        return None

    def get_metadata_by_id(self, file_id: str) -> Optional[FileMeta]:
        """Return FileMeta for a file_id, or None if not found."""
        return self._files.get(file_id)

    def update_metadata(self, file_id: str, metadata: FileMeta) -> None:
        """Replace the stored FileMeta for file_id if it exists."""
        if file_id in self._files:
            self._files[file_id] = metadata

    def delete_file(self, path: str) -> Optional[str]:
        """Remove a file entry and return its file_id, or None if the path did not
        exist."""
        path = self.normalize_path(path)
        parent, name = self.get_parent_and_name(path)
        file_id = self._path_to_id.pop(path, None)
        if file_id:
            self._files.pop(file_id, None)
            if parent in self._directories:
                self._directories[parent].discard(name)
            logger.debug(f"Deleted file: {path}")
        return file_id

    def delete_directory(self, path: str) -> None:
        """Remove an empty directory entry, raising errors for root, missing, or
        non-empty."""
        path = self.normalize_path(path)
        if path == "/":
            raise PermissionError("Cannot delete root directory")
        if not self.is_directory(path):
            raise FileNotFoundError(f"Directory does not exist: {path}")
        if self._directories[path]:
            raise OSError(f"Directory not empty: {path}")
        parent, name = self.get_parent_and_name(path)
        del self._directories[path]
        if parent in self._directories:
            self._directories[parent].discard(name)
        logger.debug(f"Deleted directory: {path}")

    def list_directory(self, path: str) -> List[str]:
        """Return the list of entry names in a directory, raising NotADirectoryError if
        not a dir."""
        path = self.normalize_path(path)
        if not self.is_directory(path):
            raise NotADirectoryError(f"Not a directory: {path}")
        return list(self._directories[path])

    def rename(self, old_path: str, new_path: str) -> None:
        """Move a file or directory from old_path to new_path, updating all child
        references."""
        old_path = self.normalize_path(old_path)
        new_path = self.normalize_path(new_path)
        if not self.path_exists(old_path):
            raise FileNotFoundError(f"Source does not exist: {old_path}")
        new_parent, new_name = self.get_parent_and_name(new_path)
        if not self.is_directory(new_parent):
            raise FileNotFoundError(f"Destination parent does not exist: {new_parent}")
        old_parent, old_name = self.get_parent_and_name(old_path)
        if self.is_file(old_path):
            file_id = self._path_to_id.pop(old_path)
            self._path_to_id[new_path] = file_id
            if file_id in self._files:
                self._files[file_id].original_name = new_name
        else:
            old_entries = self._directories.pop(old_path)
            self._directories[new_path] = old_entries
            for child_path in list(self._path_to_id.keys()):
                if child_path.startswith(old_path + "/"):
                    new_child = new_path + child_path[len(old_path):]
                    file_id = self._path_to_id.pop(child_path)
                    self._path_to_id[new_child] = file_id
        self._directories[old_parent].discard(old_name)
        self._directories[new_parent].add(new_name)
        logger.debug(f"Renamed: {old_path} -> {new_path}")

