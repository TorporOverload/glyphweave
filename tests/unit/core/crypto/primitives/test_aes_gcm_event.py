import pytest

from app.infrastructure.crypto.primitives.aes_gcm import (
    build_event_aad,
    decrypt_event_bytes,
    encrypt_event_bytes,
)


def test_event_encryption_round_trip() -> None:
    plaintext = b'{"event_id":"evt-1","type":"file_add"}'

    nonce, ciphertext = encrypt_event_bytes(
        plaintext=plaintext,
        event_hash="hash-1",
        device_id="device-a",
        master_key=b"k" * 32,
        vault_id=b"vault-1",
        version=1,
    )

    recovered = decrypt_event_bytes(
        nonce=nonce,
        ciphertext=ciphertext,
        event_hash="hash-1",
        device_id="device-a",
        master_key=b"k" * 32,
        vault_id=b"vault-1",
        version=1,
    )

    assert recovered == plaintext


def test_event_encryption_detects_aad_tampering() -> None:
    nonce, ciphertext = encrypt_event_bytes(
        plaintext=b"payload",
        event_hash="hash-1",
        device_id="device-a",
        master_key=b"k" * 32,
        vault_id=b"vault-1",
        version=1,
    )

    with pytest.raises(Exception):
        decrypt_event_bytes(
            nonce=nonce,
            ciphertext=ciphertext,
            event_hash="hash-1",
            device_id="device-b",
            master_key=b"k" * 32,
            vault_id=b"vault-1",
            version=1,
        )


def test_build_event_aad_is_stable() -> None:
    assert build_event_aad(
        event_hash="hash-1",
        version=1,
        device_id="device-a",
    ) == build_event_aad(
        event_hash="hash-1",
        version=1,
        device_id="device-a",
    )
