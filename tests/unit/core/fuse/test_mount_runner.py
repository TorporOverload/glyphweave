import json
import os

import msvcrt

from app.infrastructure.fuse.mount_runner import _read_key_material


def test_read_key_material_returns_mutable_buffer():
    read_fd, write_fd = os.pipe()
    payload = {
        "master_key_hex": "aa" * 32,
        "db_key_hex": "bb" * 32,
    }

    with os.fdopen(write_fd, "wb", closefd=True) as pipe_out:
        pipe_out.write(json.dumps(payload).encode("utf-8"))

    master_key, db_key_hex = _read_key_material(msvcrt.get_osfhandle(read_fd))

    assert isinstance(master_key, bytearray)
    assert master_key == bytearray.fromhex(payload["master_key_hex"])
    assert db_key_hex == payload["db_key_hex"]
