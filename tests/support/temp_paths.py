from __future__ import annotations

import shutil
import uuid
from pathlib import Path

import pytest

_TMP_ROOT = Path(__file__).resolve().parents[2] / ".test_tmp"


@pytest.fixture
def tmp_path() -> Path:
    """Use a workspace-local temp dir instead of pytest's basetemp."""
    _TMP_ROOT.mkdir(parents=True, exist_ok=True)
    path = _TMP_ROOT / f"gw_{uuid.uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
