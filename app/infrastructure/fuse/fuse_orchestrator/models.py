import dataclasses
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional


@dataclasses.dataclass
class MountInfo:
    """Information about an active FUSE mount."""

    file_ref_id: int
    file_name: str
    mount_dir: Path
    file_path: Path
    fs: object
    thread: Optional[threading.Thread] = None
    process: Optional[subprocess.Popen] = None
    mounted_at: float = dataclasses.field(default_factory=time.time)
