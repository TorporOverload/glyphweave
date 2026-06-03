"""Shared fixtures for VaultFileService integration tests."""

import os
from pathlib import Path

import pytest
import sqlcipher3
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("GLYPHWEAVE_DEBUG", "0")

from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.infrastructure.crypto.service.encryption_service import EncryptionService
from app.infrastructure.crypto.service.key_service import KeyService
from app.infrastructure.crypto.types import KDFParams, VaultKeyFile, WrappedKey
from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.model.search_index import register_ddl_listeners
from app.infrastructure.persistence.db.service.file_service import FileService
from app.infrastructure.persistence.db.service.folder_service import FolderService
from app.services.models import VaultContext
from app.services.vault_files.vault_file_service import VaultFileService
from app.common.paths.vault_layout import create_vault_layout


@pytest.fixture(scope="session")
def test_master_key() -> bytes:
    return b"test_master_key_32bytes_long!!"


@pytest.fixture(scope="session")
def test_vault_id_str() -> str:
    return "test_vault_001"


@pytest.fixture(scope="session")
def test_vault_id(test_vault_id_str) -> bytes:
    return test_vault_id_str.encode("utf-8")


@pytest.fixture(scope="function")
def temp_vault_path(tmp_path: Path) -> Path:
    vault_path = tmp_path / "vault"
    create_vault_layout(vault_path)
    return vault_path


@pytest.fixture(scope="function")
def local_data_path(tmp_path: Path) -> Path:
    p = tmp_path / "local"
    p.mkdir(parents=True, exist_ok=True)
    return p


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
    def _set_pragma_key(dbapi_conn, _connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute(f"PRAGMA key = \"x'{db_key_hex}'\"")
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()

    register_ddl_listeners()
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture(scope="function")
def session_factory(db_engine) -> sessionmaker:
    return sessionmaker(bind=db_engine, autoflush=False, autocommit=False)


@pytest.fixture(scope="function")
def key_service(test_master_key: bytes, test_vault_id_str: str) -> KeyService:
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
def vault_context(
    tmp_path: Path,
    temp_vault_path: Path,
    local_data_path: Path,
    test_vault_id_str: str,
    test_master_key: bytes,
    session_factory,
    encryption_service: EncryptionService,
    file_service: FileService,
    folder_service: FolderService,
) -> VaultContext:
    return VaultContext(
        app_data_dir=tmp_path,
        vault_id=test_vault_id_str,
        vault_path=temp_vault_path,
        local_data_path=local_data_path,
        session_factory=session_factory,
        encryption_service=encryption_service,
        file_service=file_service,
        folder_service=folder_service,
        master_key=SecureMemory(test_master_key),
        mounts=None,
    )


@pytest.fixture(scope="function")
def vault_file_service(vault_context: VaultContext) -> VaultFileService:
    return VaultFileService(vault_context)
