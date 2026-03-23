import stat
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FileMeta:
    """
    Metadata for an encrypted file.

    This structure stores all the information about a file EXCEPT its actual
    content. It's designed to be:

    mode: int
        POSIX file mode combining file type and permissions.
        Default: S_IFREG (regular file) | 0o644 (rw-r--r--)

        Breakdown of 0o644:
        - Owner: read + write (6 = 4 + 2)
        - Group: read only (4)
        - Others: read only (4)

        The S_IFREG flag (0o100000) marks this as a regular file vs directory.

    created_at, modified_at, accessed_at: float
        Unix timestamps (seconds since epoch) for POSIX time tracking.
        - created_at: Set once when file is created
        - modified_at: Updated on every write operation
        - accessed_at: Updated on every read operation

    ENCRYPTION NOTE:
    ----------------
    This entire structure is serialized to JSON and encrypted with AES-GCM
    before being written to disk as `meta.enc` in the file's directory.
    The encryption key is derived from the master key using HKDF with the
    file_id as context, ensuring each file's metadata has a unique key.
    """

    # Unique identifier for this file - used for key derivation and storage
    file_id: str

    # Display name in filesystem (can be renamed without re-encrypting content)
    original_name: str

    # Unencrypted file size in bytes (what the OS sees)
    plaintext_size: int

    # File type + permissions (default: regular file with rw-r--r--)
    mode: int = stat.S_IFREG | 0o644

    # Unix timestamp when file was created (set once)
    created_at: float = field(default_factory=time.time)

    # Unix timestamp of last modification (updated on write)
    modified_at: float = field(default_factory=time.time)

    # Unix timestamp of last access (updated on read)
    accessed_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        """
        Serialize metadata to a dictionary for JSON encoding.
        """
        return {
            "file_id": self.file_id,
            "original_name": self.original_name,
            "plaintext_size": self.plaintext_size,
            "mode": self.mode,
            "created_at": self.created_at,
            "modified_at": self.modified_at,
            "accessed_at": self.accessed_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FileMeta":
        """
        Deserialize metadata from a dictionary.
        Args:
            data: Dictionary with all required fields (must match to_dict output)
        Returns:
            FileMeta: Reconstructed metadata object

        Note: Missing fields will raise KeyError
        """
        return cls(**data)


@dataclass
class DirMeta:
    """
    Metadata for an encrypted directory.

    """

    # Unique identifier for this directory
    dir_id: str

    # Directory name (final path component only)
    name: str

    # Parent directory ID (None for root "/")
    parent_id: Optional[str]

    # Directory type + permissions (default: drwxr-xr-x)
    mode: int = stat.S_IFDIR | 0o755

    # Unix timestamp when directory was created
    created_at: float = field(default_factory=time.time)

    # Unix timestamp of last modification (file added/removed)
    modified_at: float = field(default_factory=time.time)

