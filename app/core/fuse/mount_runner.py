#!/usr/bin/env python3
"""
Run a single-file FUSE mount in a dedicated process (Windows/WinFsp).

This is used to allow clean unmounts by sending CTRL_BREAK_EVENT to the
FUSE process group.

- Master key and DB key arrive via an inherited Win32 anonymous pipe, not CLI args.
- Keys are converted from hex strings into a mutable bytearray immediately and
  then consumed into SecureMemory as soon as possible.
- Intermediate hex string is deleted
- The paging window (JSON payload → hex string → mutable bytes → SecureMemory) is
  minimized by reordering operations: key_service (with SecureMemory) is
  initialized before DbBase, ensuring VirtualLock is active before DB ops.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from mfusepy import FUSE

from app.config import get_vaults_data_dir
from app.core.crypto.primitives.secure_memory import SecureMemory
from app.core.crypto.service.key_service import KeyService
from app.core.crypto.service.utils import load_vault_key
from app.core.database.base import DbBase
from app.core.database.service.file_service import FileService
from app.core.runtime_layout import runtime_cache_dir
from app.core.fuse.single_fs import SingleFileFS
from app.core.vault_layout import vault_key_path


def _parse_args() -> argparse.Namespace:
    """Parse and return CLI arguments for the FUSE mount runner subprocess."""
    parser = argparse.ArgumentParser(description="GlyphWeave FUSE mount runner")
    parser.add_argument("--vault-id", required=True)
    parser.add_argument("--vault-path", required=True)
    parser.add_argument("--file-ref-id", required=True)
    parser.add_argument("--mount-dir", required=True)
    parser.add_argument("--mount-file-name")
    parser.add_argument("--vaults-data-dir")
    parser.add_argument("--key-pipe-handle", required=True, type=int)
    return parser.parse_args()


def _read_key_material(pipe_handle: int) -> tuple[bytearray, str]:
    """Read and parse key material from the inherited anonymous pipe handle.

    Returns:
        (master_key_bytes, db_key_hex) where master_key_bytes is a mutable buffer
        ready for immediate wrapping in SecureMemory, minimizing paging exposure.
    """
    import msvcrt

    pipe_fd = msvcrt.open_osfhandle(
        pipe_handle, os.O_RDONLY | getattr(os, "O_BINARY", 0)
    )
    with os.fdopen(pipe_fd, "rb", closefd=True) as pipe_in:
        payload = pipe_in.read()

    data = json.loads(payload.decode("utf-8"))
    master_key_hex = data.get("master_key_hex")
    db_key_hex = data.get("db_key_hex")
    if not isinstance(master_key_hex, str) or not isinstance(db_key_hex, str):
        raise ValueError("Invalid key payload")

    # Convert hex to a mutable bytearray immediately to minimize paging window.
    # The intermediate string is still in Python's memory, but the mutable buffer
    # will be consumed into SecureMemory on the next line in main().
    master_key_bytes = bytearray.fromhex(master_key_hex)

    # Zero the temporary hex string in memory (best-effort, may not survive GC)
    # This is defence-in-depth; SecureMemory wrapping is the primary defence
    del master_key_hex

    return master_key_bytes, db_key_hex


def main() -> int:
    """Initialize key material, build SingleFileFS, and run the WinFsp FUSE loop."""
    if os.name != "nt":
        raise OSError("GlyphWeave mount runner is only supported on Windows")

    args = _parse_args()

    vault_path = Path(args.vault_path)
    file_ref_id = int(args.file_ref_id)
    mount_dir = Path(args.mount_dir)
    vaults_data_dir = (
        Path(args.vaults_data_dir) if args.vaults_data_dir else get_vaults_data_dir()
    )
    cache_dir = runtime_cache_dir(vaults_data_dir / args.vault_id)
    master_key_bytes, db_key_hex = _read_key_material(args.key_pipe_handle)

    # Wrap master key in SecureMemory immediately before any other processing.
    # On Windows this copies the bytes into a dedicated VirtualAlloc region,
    # zeroes the temporary mutable source buffer, and locks the page-backed region.
    key_service = KeyService()
    key_service.vault_key_file = load_vault_key(vault_key_path(vault_path))
    key_service.master_key = SecureMemory.consume_mutable(master_key_bytes)

    # Now safe to proceed with DB operations; master key is locked in memory
    db = DbBase(args.vault_id, db_key_hex, vaults_data_dir=vaults_data_dir)
    session_factory = db.SessionLocal
    file_service = FileService(session_factory)

    file_ref = file_service.get_file_reference_with_blobs(file_ref_id)
    if not file_ref or not file_ref.file_entry:
        return 1

    entry = file_ref.file_entry
    blob_ids = sorted(
        [b.blob_id for b in entry.blobs],
        key=lambda bid: next(b.blob_index for b in entry.blobs if b.blob_id == bid),
    )

    session = session_factory()
    fs = SingleFileFS(
        file_name=args.mount_file_name or file_ref.name,
        file_id=entry.file_id,
        file_ref_id=file_ref_id,
        plaintext_size=entry.original_size_bytes,
        blob_ids=blob_ids,
        vault_path=vault_path,
        cache_dir=cache_dir,
        mount_dir=mount_dir,
        key_service=key_service,
        vault_id=args.vault_id.encode("utf-8"),
        db_session=session,
        # master_key=key_service.master_key.get(),
    )

    fuse_kwargs: dict = {
        "foreground": True,
        "nothreads": False,
        "uid": -1,
        "gid": -1,
        "umask": 0,
        "FileSystemName": "NTFS",
        "attr_timeout": -1,
        "entry_timeout": -1,
        "negative_timeout": 0,
        "FileInfoTimeout": -1,
    }
    FUSE(fs, str(mount_dir), **fuse_kwargs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
