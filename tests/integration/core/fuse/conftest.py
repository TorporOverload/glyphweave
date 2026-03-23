"""Shared fixtures for the FUSE integration test package."""

import os
from pathlib import Path
from typing import Generator

import pytest
import sqlcipher3
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("GLYPHWEAVE_DEBUG", "0")

from app.infrastructure.crypto.service.encryption_service import EncryptionService
from app.infrastructure.crypto.service.key_service import KeyService
from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.file_reference import FileReference
from app.infrastructure.persistence.db.service.file_service import FileService
from app.infrastructure.persistence.db.service.folder_service import FolderService
from app.infrastructure.persistence.db.service.gc_service import GarbageCollector
from app.infrastructure.persistence.db.service.wal_service import WalService
from app.infrastructure.fuse.chunk_store import ChunkStore
from app.infrastructure.fuse.temp_store import TempStore
from app.common.paths.vault_layout import create_vault_layout
from tests.support.fuse_builders import build_single_file_fs, create_encrypted_file_in_vault


@pytest.fixture(scope="session")
def test_master_key() -> bytes:
    return b"test_master_key_32bytes_long!!"


@pytest.fixture(scope="session")
def test_vault_id() -> bytes:
    return b"test_vault_001"


@pytest.fixture(scope="session")
def test_vault_id_str() -> str:
    return "test_vault_001"


@pytest.fixture(scope="function")
def temp_vault_path(tmp_path: Path) -> Path:
    vault_path = tmp_path / "vault"
    create_vault_layout(vault_path)
    return vault_path


@pytest.fixture(scope="function")
def temp_mount_path(tmp_path: Path) -> Path:
    mount_path = tmp_path / "fuse_mount"
    mount_path.mkdir(parents=True, exist_ok=True)
    return mount_path


@pytest.fixture(scope="function")
def temp_runtime_cache_dir(tmp_path: Path) -> Path:
    cache_dir = tmp_path / "runtime" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


@pytest.fixture(scope="function")
def db_engine(temp_vault_path: Path, test_master_key: bytes, test_vault_id: bytes):
    from app.infrastructure.crypto.primitives.key_derivation import derive_subkey
    from app.infrastructure.crypto.types import KeyPurpose

    db_path = temp_vault_path / "test.db"
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

    Base.metadata.create_all(engine)

    yield engine

    engine.dispose()


@pytest.fixture(scope="function")
def session_factory(db_engine) -> sessionmaker:
    return sessionmaker(bind=db_engine, autoflush=False, autocommit=False)


@pytest.fixture(scope="function")
def db_session(session_factory) -> Generator:
    session = session_factory()

    yield session

    session.rollback()
    session.close()


@pytest.fixture(scope="function")
def key_service(test_master_key: bytes, test_vault_id_str: str) -> KeyService:
    from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
    from app.infrastructure.crypto.types import KDFParams, VaultKeyFile, WrappedKey

    service = KeyService()
    service.master_key = SecureMemory(test_master_key)

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
    return EncryptionService()


@pytest.fixture(scope="function")
def file_service(session_factory) -> FileService:
    return FileService(session_factory)


@pytest.fixture(scope="function")
def folder_service(session_factory, temp_vault_path: Path) -> FolderService:
    return FolderService(session_factory, temp_vault_path)


@pytest.fixture(scope="function")
def garbage_collector(session_factory, temp_vault_path: Path) -> GarbageCollector:
    return GarbageCollector(session_factory, temp_vault_path)


@pytest.fixture(scope="function")
def temp_store(temp_runtime_cache_dir: Path, key_service: KeyService) -> TempStore:
    return TempStore(cache_dir=temp_runtime_cache_dir, key_service=key_service)


@pytest.fixture(scope="function")
def wal_service(session_factory, temp_store: TempStore) -> WalService:
    return WalService(session_factory=session_factory, temp_store=temp_store)


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
    content = b"Hello, GlyphWeave! This is a test file for FUSE testing."
    file_path = tmp_path / "small_test.txt"
    file_path.write_bytes(content)
    return file_path, content


@pytest.fixture(scope="function")
def sample_medium_file(tmp_path: Path) -> tuple[Path, bytes]:
    content = os.urandom(100 * 1024)
    file_path = tmp_path / "medium_test.bin"
    file_path.write_bytes(content)
    return file_path, content


@pytest.fixture(scope="function")
def sample_large_file(tmp_path: Path) -> tuple[Path, bytes]:
    content = os.urandom(500 * 1024)
    file_path = tmp_path / "large_test.bin"
    file_path.write_bytes(content)
    return file_path, content


@pytest.fixture(scope="function")
def encrypted_file_in_vault(
    temp_vault_path: Path,
    encryption_service: EncryptionService,
    file_service: FileService,
    test_master_key: bytes,
    test_vault_id: bytes,
    sample_small_file: tuple[Path, bytes],
) -> tuple[FileReference, bytes]:
    file_path, original_content = sample_small_file
    return create_encrypted_file_in_vault(
        temp_vault_path=temp_vault_path,
        encryption_service=encryption_service,
        file_service=file_service,
        test_master_key=test_master_key,
        test_vault_id=test_vault_id,
        source_file=file_path,
        original_content=original_content,
        file_name="test_file.txt",
        mime_type="text/plain",
    )


@pytest.fixture(scope="function")
def encrypted_large_file_in_vault(
    temp_vault_path: Path,
    encryption_service: EncryptionService,
    file_service: FileService,
    test_master_key: bytes,
    test_vault_id: bytes,
    sample_large_file: tuple[Path, bytes],
) -> tuple[FileReference, bytes]:
    file_path, original_content = sample_large_file
    return create_encrypted_file_in_vault(
        temp_vault_path=temp_vault_path,
        encryption_service=encryption_service,
        file_service=file_service,
        test_master_key=test_master_key,
        test_vault_id=test_vault_id,
        source_file=file_path,
        original_content=original_content,
        file_name="large_test.bin",
        mime_type="application/octet-stream",
    )


@pytest.fixture(scope="function")
def single_fs(
    encrypted_file_in_vault,
    temp_vault_path: Path,
    temp_runtime_cache_dir: Path,
    temp_mount_path: Path,
    key_service: KeyService,
    test_vault_id: bytes,
    test_master_key: bytes,
    session_factory,
):
    """SingleFileFS backed by a small encrypted file."""
    file_ref, original_content = encrypted_file_in_vault
    fs = build_single_file_fs(
        file_ref=file_ref,
        temp_vault_path=temp_vault_path,
        temp_runtime_cache_dir=temp_runtime_cache_dir,
        temp_mount_path=temp_mount_path,
        key_service=key_service,
        test_vault_id=test_vault_id,
        test_master_key=test_master_key,
        session_factory=session_factory,
    )

    yield fs, original_content

    fs.handle_manager.close_all(flush=False)


@pytest.fixture(scope="function")
def large_file_fs(
    encrypted_large_file_in_vault,
    temp_vault_path: Path,
    temp_runtime_cache_dir: Path,
    temp_mount_path: Path,
    key_service: KeyService,
    test_vault_id: bytes,
    test_master_key: bytes,
    session_factory,
):
    """SingleFileFS backed by a multi-chunk encrypted file."""
    file_ref, original_content = encrypted_large_file_in_vault
    fs = build_single_file_fs(
        file_ref=file_ref,
        temp_vault_path=temp_vault_path,
        temp_runtime_cache_dir=temp_runtime_cache_dir,
        temp_mount_path=temp_mount_path,
        key_service=key_service,
        test_vault_id=test_vault_id,
        test_master_key=test_master_key,
        session_factory=session_factory,
    )

    yield fs, original_content

    fs.handle_manager.close_all(flush=False)


@pytest.fixture(scope="function")
def recovery_fs(
    encrypted_file_in_vault,
    temp_vault_path: Path,
    temp_runtime_cache_dir: Path,
    temp_mount_path: Path,
    key_service: KeyService,
    test_vault_id: bytes,
    test_master_key: bytes,
    session_factory,
):
    """SingleFileFS fixture kept separate for recovery scenarios."""
    file_ref, original_content = encrypted_file_in_vault
    fs = build_single_file_fs(
        file_ref=file_ref,
        temp_vault_path=temp_vault_path,
        temp_runtime_cache_dir=temp_runtime_cache_dir,
        temp_mount_path=temp_mount_path,
        key_service=key_service,
        test_vault_id=test_vault_id,
        test_master_key=test_master_key,
        session_factory=session_factory,
    )

    yield fs, original_content

    fs.handle_manager.close_all(flush=False)
