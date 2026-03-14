"""
Fixtures for FUSE module tests.

Provides:
- Test vault setup with SQLCipher database
- Key service with test master key
- Sample encrypted files in the vault
- WAL service and temp blob store
"""

import hashlib
import os
import secrets
from pathlib import Path
from typing import Generator

import pytest
import sqlcipher3
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.core.crypto.service.encryption_service import EncryptionService
from app.core.crypto.service.key_service import KeyService
from app.core.database.base import Base
from app.core.database.model.file_reference import FileReference
from app.core.database.service.file_service import FileService
from app.core.database.service.folder_service import FolderService
from app.core.database.service.gc_service import GarbageCollector
from app.core.database.service.wal_service import WalService
from app.core.fuse.chunk_store import ChunkStore
from app.core.fuse.temp_store import TempStore
from app.core.vault_layout import ensure_vault_layout, resolve_blob_path


# Test directories
TEST_FILES_DIR = Path(__file__).parent.parent.parent.parent / "test_files"
SAMPLE_FILES_DIR = TEST_FILES_DIR / "files"
VAULT_DIR = TEST_FILES_DIR / "vault"
FUSE_MOUNT_DIR = TEST_FILES_DIR / "fuse"


@pytest.fixture(scope="session")
def test_master_key() -> bytes:
    """32-byte test master key."""
    return b"test_master_key_32bytes_long!!"


@pytest.fixture(scope="session")
def test_vault_id() -> bytes:
    """Test vault identifier."""
    return b"test_vault_001"


@pytest.fixture(scope="session")
def test_vault_id_str() -> str:
    """Test vault identifier as string."""
    return "test_vault_001"


@pytest.fixture(scope="function")
def temp_vault_path(tmp_path: Path) -> Path:
    """Create a temporary vault directory for each test."""
    vault_path = tmp_path / "vault"
    ensure_vault_layout(vault_path)
    return vault_path


@pytest.fixture(scope="function")
def temp_mount_path(tmp_path: Path) -> Path:
    """Create a temporary mount directory for each test."""
    mount_path = tmp_path / "fuse_mount"
    mount_path.mkdir(parents=True, exist_ok=True)
    return mount_path


@pytest.fixture(scope="function")
def temp_runtime_cache_dir(tmp_path: Path) -> Path:
    """Create a local runtime cache directory separate from the vault."""
    cache_dir = tmp_path / "runtime" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


@pytest.fixture(scope="function")
def db_engine(temp_vault_path: Path, test_master_key: bytes, test_vault_id: bytes):
    """Create a SQLCipher database engine for testing."""
    from app.core.crypto.primitives.key_derivation import derive_subkey
    from app.core.crypto.types import KeyPurpose

    db_path = temp_vault_path / "test.db"

    # Derive database key from master key
    db_key_bytes = derive_subkey(
        test_master_key, test_vault_id, KeyPurpose.DATABASE, "db_encryption"
    )
    db_key_hex = db_key_bytes.hex()

    engine = create_engine(
        f"sqlite:///{db_path}",
        module=sqlcipher3,
        future=True,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _set_pragma_key(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute(f"PRAGMA key = \"x'{db_key_hex}'\"")
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()

    # Create all tables
    Base.metadata.create_all(engine)

    yield engine

    engine.dispose()


@pytest.fixture(scope="function")
def session_factory(db_engine) -> sessionmaker:
    """Create a session factory for each test.

    This is the primary fixture for the new session-per-operation pattern.
    Services receive this factory and create their own short-lived sessions.
    """
    return sessionmaker(bind=db_engine, autoflush=False, autocommit=False)


@pytest.fixture(scope="function")
def db_session(session_factory) -> Generator:
    """Create a database session for each test.

    Used for direct DB operations in test setup/teardown (e.g. verifying
    state). Services should use session_factory instead.
    """
    session = session_factory()

    yield session

    session.rollback()
    session.close()


@pytest.fixture(scope="function")
def key_service(test_master_key: bytes, test_vault_id_str: str) -> KeyService:
    """Create a KeyService instance with the test master key."""
    from app.core.crypto.primitives.secure_memory import SecureMemory
    from app.core.crypto.types import VaultKeyFile, WrappedKey, KDFParams

    service = KeyService()
    # Manually set the master key for testing
    service.master_key = SecureMemory(test_master_key)

    # Create a minimal vault_key_file for derive_sub_key to work
    # (it needs vault_id for HKDF context)
    dummy_wrapped = WrappedKey(
        ciphertext=b"\x00" * 40,
        salt=b"\x00" * 16,
        kdf_params=KDFParams(),
    )
    service.vault_key_file = VaultKeyFile(
        password_wrapped=dummy_wrapped,
        recovery_wrapped=dummy_wrapped,
        check_nonce=b"\x00" * 16,
        check_value=b"\x00" * 32,
        vault_id=test_vault_id_str,
        recovery_phrase_wrapped=b"\x00" * 64,
    )
    return service


@pytest.fixture(scope="function")
def encryption_service() -> EncryptionService:
    """Create an EncryptionService instance."""
    return EncryptionService()


@pytest.fixture(scope="function")
def file_service(session_factory) -> FileService:
    """Create a FileService instance."""
    return FileService(session_factory)


@pytest.fixture(scope="function")
def folder_service(session_factory, temp_vault_path: Path) -> FolderService:
    """Create a FolderService instance."""
    return FolderService(session_factory, temp_vault_path)


@pytest.fixture(scope="function")
def garbage_collector(session_factory, temp_vault_path: Path) -> GarbageCollector:
    """Create a GarbageCollector instance."""
    return GarbageCollector(session_factory, temp_vault_path)


@pytest.fixture(scope="function")
def temp_store(
    temp_runtime_cache_dir: Path,
    key_service: KeyService,
) -> TempStore:
    """Create a TempStore instance."""
    return TempStore(
        cache_dir=temp_runtime_cache_dir,
        key_service=key_service,
    )


@pytest.fixture(scope="function")
def wal_service(session_factory, temp_store: TempStore) -> WalService:
    """Create a WalService instance."""
    return WalService(
        session_factory=session_factory,
        temp_store=temp_store,
    )


@pytest.fixture(scope="function")
def chunk_store(
    temp_vault_path: Path,
    temp_runtime_cache_dir: Path,
    key_service: KeyService,
    test_vault_id: bytes,
    file_service: FileService,
    folder_service: FolderService,
    garbage_collector: GarbageCollector,
) -> ChunkStore:
    """Create a ChunkStore instance."""
    return ChunkStore(
        vault_path=temp_vault_path,
        cache_dir=temp_runtime_cache_dir,
        key_service=key_service,
        vault_id=test_vault_id,
        file_service=file_service,
        folder_service=folder_service,
        gc=garbage_collector,
    )


@pytest.fixture(scope="function")
def sample_small_file(tmp_path: Path) -> tuple[Path, bytes]:
    """Create a small test file and return (path, content)."""
    content = b"Hello, GlyphWeave! This is a test file for FUSE testing."
    file_path = tmp_path / "small_test.txt"
    file_path.write_bytes(content)
    return file_path, content


@pytest.fixture(scope="function")
def sample_medium_file(tmp_path: Path) -> tuple[Path, bytes]:
    """Create a medium test file (~100KB) and return (path, content)."""
    content = os.urandom(100 * 1024)  # 100KB
    file_path = tmp_path / "medium_test.bin"
    file_path.write_bytes(content)
    return file_path, content


@pytest.fixture(scope="function")
def sample_large_file(tmp_path: Path) -> tuple[Path, bytes]:
    """Create a larger test file (~500KB) spanning multiple chunks."""
    content = os.urandom(500 * 1024)  # 500KB = ~8 chunks at 64KB each
    file_path = tmp_path / "large_test.bin"
    file_path.write_bytes(content)
    return file_path, content


@pytest.fixture(scope="function")
def encrypted_file_in_vault(
    temp_vault_path: Path,
    encryption_service: EncryptionService,
    file_service: FileService,
    key_service: KeyService,
    test_master_key: bytes,
    test_vault_id: bytes,
    sample_small_file: tuple[Path, bytes],
) -> tuple[FileReference, bytes]:
    """
    Encrypt a sample file and add it to the vault.

    Returns (FileReference, original_content).
    """
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

    # Calculate content hash and sizes
    content_hash = hashlib.sha256(original_content).hexdigest()
    encrypted_size = sum(
        resolve_blob_path(temp_vault_path, bid).stat().st_size for bid in blob_ids
    )

    # Create FileEntry (auto-commits via session_scope)
    file_entry = file_service.create_file_entry_with_blobs(
        file_id=file_id,
        content_hash=content_hash,
        mime_type="text/plain",
        encrypted_size=encrypted_size,
        original_size=len(original_content),
        blob_ids=blob_ids,
    )

    # Create FileReference (auto-commits via session_scope)
    file_ref = file_service.create_file_reference(
        name="test_file.txt",
        parent_id=None,
        file_entry_id=file_entry.id,
    )

    return file_ref, original_content


@pytest.fixture(scope="function")
def encrypted_large_file_in_vault(
    temp_vault_path: Path,
    encryption_service: EncryptionService,
    file_service: FileService,
    key_service: KeyService,
    test_master_key: bytes,
    test_vault_id: bytes,
    sample_large_file: tuple[Path, bytes],
) -> tuple[FileReference, bytes]:
    """
    Encrypt a large sample file (multi-chunk) and add it to the vault.

    Returns (FileReference, original_content).
    """
    file_path, original_content = sample_large_file
    file_id = secrets.token_hex(16)

    # Encrypt the file
    blob_ids = encryption_service.encrypt_file(
        file_path=file_path,
        vault_path=temp_vault_path,
        master_key=test_master_key,
        vault_id=test_vault_id,
        file_id=file_id,
    )

    # Calculate content hash and sizes
    content_hash = hashlib.sha256(original_content).hexdigest()
    encrypted_size = sum(
        resolve_blob_path(temp_vault_path, bid).stat().st_size for bid in blob_ids
    )

    # Create FileEntry (auto-commits via session_scope)
    file_entry = file_service.create_file_entry_with_blobs(
        file_id=file_id,
        content_hash=content_hash,
        mime_type="application/octet-stream",
        encrypted_size=encrypted_size,
        original_size=len(original_content),
        blob_ids=blob_ids,
    )

    # Create FileReference (auto-commits via session_scope)
    file_ref = file_service.create_file_reference(
        name="large_test.bin",
        parent_id=None,
        file_entry_id=file_entry.id,
    )

    return file_ref, original_content
