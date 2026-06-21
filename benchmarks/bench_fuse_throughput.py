"""FUSE I/O throughput:
in-process ops layer + real WinFsp mount, escalate size to failure."""

from __future__ import annotations

import argparse
import csv
import os
import secrets
import shutil
from pathlib import Path
from time import perf_counter

import sqlcipher3
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.common.paths.vault_layout import create_vault_layout
from app.infrastructure.crypto.primitives.key_derivation import derive_subkey
from app.infrastructure.crypto.primitives.secure_memory import SecureMemory
from app.infrastructure.crypto.service.encryption_service import EncryptionService
from app.infrastructure.crypto.service.key_service import KeyService
from app.infrastructure.crypto.types import (
    KDFParams,
    KeyPurpose,
    VaultKeyFile,
    WrappedKey,
)
from app.infrastructure.fuse.single_fs.main_ops import (
    open_op,
    read_op,
    release_op,
    write_op,
)
from app.infrastructure.persistence.db.base import Base
from app.infrastructure.persistence.db.service.file_service import FileService
from benchmarks import _harness as H
from tests.support.fuse_builders import (
    build_single_file_fs,
    create_encrypted_file_in_vault,
)

MASTER_KEY = b"benchmark_master_key_32bytes!!!!"[:32]
VAULT_ID = b"bench_vault_fuse"
BLOCK = 1 * 1024 * 1024  # 1 MiB I/O block
LADDER = [
    64 * 1024,
    256 * 1024,
    1 << 20,
    5 << 20,
    20 << 20,
    50 << 20,
    100 << 20,
    250 << 20,
    500 << 20,
    1 << 30,
    2 << 30,
    4 << 30,
]
DISK_MARGIN = 2 << 30  # keep 2 GiB free


def _inprocess_fs(workdir: Path, size: int):
    """Build a SingleFileFS over an encrypted file of `size` bytes"""
    vault = workdir / "vault"
    create_vault_layout(vault)
    cache = workdir / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    mount = workdir / "mnt"
    mount.mkdir(parents=True, exist_ok=True)

    db_path = vault / "test.db"
    db_key = derive_subkey(
        MASTER_KEY, VAULT_ID, KeyPurpose.DATABASE, "db_encryption"
    ).hex()
    engine = create_engine(
        f"sqlite:///{db_path}",
        module=sqlcipher3,
        future=True,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _key(conn, _rec):
        cur = conn.cursor()
        cur.execute(f"PRAGMA key = \"x'{db_key}'\"")
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA foreign_keys = ON")
        cur.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    file_service = FileService(factory)

    ks = KeyService()
    ks.master_key = SecureMemory(MASTER_KEY)
    dummy = WrappedKey(
        ciphertext=b"\x00" * 40, salt=b"\x00" * 16, kdf_params=KDFParams()
    )
    ks.vault_key_file = VaultKeyFile(
        password_wrapped=dummy,
        recovery_wrapped=dummy,
        check_nonce=b"\x00" * 16,
        check_value=b"\x00" * 32,
        vault_id=VAULT_ID.decode(errors="ignore"),
        recovery_phrase_wrapped=b"\x00" * 64,
    )

    content = secrets.token_bytes(size)
    src = workdir / "src.bin"
    src.write_bytes(content)
    file_ref, _ = create_encrypted_file_in_vault(
        temp_vault_path=vault,
        encryption_service=EncryptionService(),
        file_service=file_service,
        test_master_key=MASTER_KEY,
        test_vault_id=VAULT_ID,
        source_file=src,
        original_content=content,
        file_name="bench.bin",
        mime_type="application/octet-stream",
    )
    fs = build_single_file_fs(
        file_ref=file_ref,
        temp_vault_path=vault,
        temp_runtime_cache_dir=cache,
        temp_mount_path=mount,
        key_service=ks,
        test_vault_id=VAULT_ID,
        test_master_key=MASTER_KEY,
        session_factory=factory,
    )
    return fs, content, engine


def _inprocess_rw(workdir: Path, size: int) -> tuple[float, float]:
    fs, content, engine = _inprocess_fs(workdir, size)
    main = "/" + fs.file_name
    try:
        # write
        fh = open_op(fs, main, os.O_RDWR)
        start = perf_counter()
        off = 0
        while off < size:
            chunk = content[off : off + BLOCK]
            write_op(fs, main, chunk, off, fh)
            off += len(chunk)
        release_op(fs, main, fh)  # flush dirty chunks to blobs
        write_s = perf_counter() - start
        # read
        fh2 = open_op(fs, main, os.O_RDONLY)
        start = perf_counter()
        off = 0
        while off < size:
            data = read_op(fs, main, BLOCK, off, fh2)
            if not data:
                break
            off += len(data)
        read_s = perf_counter() - start
        release_op(fs, main, fh2)
        return write_s, read_s
    finally:
        fs.handle_manager.close_all(flush=False)
        engine.dispose()


def _realmount_rw(workdir: Path, size: int) -> tuple[float, float]:
    content = secrets.token_bytes(size)
    src = workdir / "rm_src.bin"
    src.write_bytes(content)
    with H.temp_vault(workdir) as svc:
        svc.add_file(src, dest_name="rm_bench.bin")
        ref = next(e for e in svc.list_root_entries() if not e.is_folder)
        mounted = H.mount_and_wait(svc, ref.id)
        # write
        start = perf_counter()
        with mounted.open("r+b") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        write_s = perf_counter() - start
        # read
        start = perf_counter()
        with mounted.open("rb") as fh:
            while fh.read(BLOCK):
                pass
        read_s = perf_counter() - start
        return write_s, read_s


def _mbps(size: int, seconds: float) -> float:
    return (size / (1024 * 1024)) / seconds if seconds > 0 else 0.0


def run(
    workdir: Path, *, quick: bool = False, max_file_size: int | None = None
) -> None:
    workdir.mkdir(parents=True, exist_ok=True)
    ladder = [64 * 1024, 1 << 20, 5 << 20] if quick else list(LADDER)
    if max_file_size:
        ladder = [s for s in ladder if s <= max_file_size]

    csv_path = H.RAW_DIR / "fuse_throughput.csv"
    csv_fields = [
        "layer",
        "op",
        "file_size_bytes",
        "run_idx",
        "elapsed_s",
        "throughput_mbps",
        "status",
    ]

    # Load any results from a previous interrupted run.
    all_rows: list[dict] = []
    done: set[tuple[str, int]] = set()
    if csv_path.exists():
        with csv_path.open(encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if row["status"] == "ok":
                    all_rows.append(row)
                    done.add((row["layer"], int(row["file_size_bytes"])))

    layers = {"in_process": _inprocess_rw}
    if not quick:
        layers["real_mount"] = _realmount_rw  # WinFsp required

    for layer, fn in layers.items():
        for size in ladder:
            if (layer, size) in done:
                print(
                    f"[fuse] skipping {layer} {size // (1 << 20) or size // 1024} "
                    f"{'MiB' if size >= (1 << 20) else 'KiB'} (already done)"
                )
                continue
            if H.free_disk_bytes(workdir) < DISK_MARGIN + size * 3:
                all_rows.append(
                    {
                        "layer": layer,
                        "op": "write",
                        "file_size_bytes": size,
                        "run_idx": 0,
                        "elapsed_s": "",
                        "throughput_mbps": "",
                        "status": "skipped_disk_guard",
                    }
                )
                break
            sub = workdir / f"{layer}_{size}"
            if sub.exists():
                shutil.rmtree(sub)
            sub.mkdir(parents=True, exist_ok=True)
            try:
                write_s, read_s = fn(sub, size)
                all_rows.append(
                    {
                        "layer": layer,
                        "op": "write",
                        "file_size_bytes": size,
                        "run_idx": 0,
                        "elapsed_s": write_s,
                        "throughput_mbps": _mbps(size, write_s),
                        "status": "ok",
                    }
                )
                all_rows.append(
                    {
                        "layer": layer,
                        "op": "read",
                        "file_size_bytes": size,
                        "run_idx": 0,
                        "elapsed_s": read_s,
                        "throughput_mbps": _mbps(size, read_s),
                        "status": "ok",
                    }
                )
                H.write_csv(csv_path, all_rows, csv_fields)
            except (
                Exception
            ) as exc:  # escalate-until-failure: record and stop this layer
                all_rows.append(
                    {
                        "layer": layer,
                        "op": "write",
                        "file_size_bytes": size,
                        "run_idx": 0,
                        "elapsed_s": "",
                        "throughput_mbps": "",
                        "status": f"FAILED: {type(exc).__name__}: {exc}",
                    }
                )
                H.write_csv(csv_path, all_rows, csv_fields)
                break

    rows = all_rows
    H.write_csv(csv_path, rows, csv_fields)

    def _summary(layer: str, op: str) -> str:
        ok = [
            r
            for r in rows
            if r["layer"] == layer and r["op"] == op and r["status"] == "ok"
        ]
        if not ok:
            return "no successful runs"
        best = max(ok, key=lambda r: int(r["file_size_bytes"]))
        peak = max(float(r["throughput_mbps"]) for r in ok)
        return f"peak={peak:.1f} MB/s; max size sustained={
            int(best['file_size_bytes']) / (1 << 20):.0f} MiB"

    sections = []
    for layer in layers:
        for op in ("write", "read"):
            sections.append((f"{layer} / {op}", _summary(layer, op)))
    sections.append(
        (
            "Caveat",
            "Real-mount reads may be inflated by the Windows/WinFsp page cache; "
            "the in-process layer is cache-free.",
        )
    )
    H.write_txt(
        H.RAW_DIR / "fuse_throughput.txt", "FUSE I/O Throughput Benchmark", sections
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="1. FUSE throughput benchmark")
    parser.add_argument(
        "--workdir", type=Path, default=H.REPO_ROOT / "benchmarks" / ".vaults" / "fuse"
    )
    parser.add_argument("--quick", action="store_true")
    parser.add_argument(
        "--max-file-size", type=int, default=None, help="ceiling in bytes"
    )
    args = parser.parse_args()
    run(args.workdir, quick=args.quick, max_file_size=args.max_file_size)
    from benchmarks.plotting import plot_fuse_throughput

    plot_fuse_throughput(H.RAW_DIR)


if __name__ == "__main__":
    main()
