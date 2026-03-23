from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


def hlc_to_tuple(hlc: Mapping[str, Any]) -> tuple[int, int, str]:
    """Convert an HLC mapping into a comparable tuple."""
    return (int(hlc["wall_time"]), int(hlc["logical"]), str(hlc["device_id"]))


def compare_hlc(a: Mapping[str, Any], b: Mapping[str, Any]) -> int:
    """Compare two Hybrid Logical Clock values."""
    a_tuple = hlc_to_tuple(a)
    b_tuple = hlc_to_tuple(b)
    if a_tuple < b_tuple:
        return -1
    if a_tuple > b_tuple:
        return 1
    return 0


def is_hlc_after(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    """Return True when HLC ``a`` is strictly after ``b``."""
    return compare_hlc(a, b) > 0


def is_hlc_before(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    """Return True when HLC ``a`` is strictly before ``b``."""
    return compare_hlc(a, b) < 0


@dataclass
class HLCClock:
    """Stateful Hybrid Logical Clock with local tick and remote observe operations."""

    device_id: str
    wall_time: int = 0
    logical: int = 0

    def next(self) -> tuple[int, int, str]:
        """Advance the local clock for a newly emitted event."""
        physical_time = self._physical_time_ms()
        if physical_time > self.wall_time:
            self.wall_time = physical_time
            self.logical = 0
        else:
            self.logical += 1
        return (self.wall_time, self.logical, self.device_id)

    def observe(self, remote_hlc: Mapping[str, Any]) -> tuple[int, int, str]:
        """Merge an observed remote clock into local state."""
        remote_wall_time, remote_logical, _ = hlc_to_tuple(remote_hlc)
        physical_time = self._physical_time_ms()
        max_wall_time = max(physical_time, self.wall_time, remote_wall_time)

        if (
            max_wall_time == physical_time
            and max_wall_time > self.wall_time
            and max_wall_time > remote_wall_time
        ):
            self.wall_time = physical_time
            self.logical = 0
        elif max_wall_time == self.wall_time and max_wall_time == remote_wall_time:
            self.logical = max(self.logical, remote_logical) + 1
        elif max_wall_time == self.wall_time:
            self.logical += 1
        else:
            self.wall_time = remote_wall_time
            self.logical = remote_logical + 1

        self.wall_time = max_wall_time
        return (self.wall_time, self.logical, self.device_id)

    def to_hlc(self) -> dict[str, Any]:
        return {
            "wall_time": self.wall_time,
            "logical": self.logical,
            "device_id": self.device_id,
        }

    @staticmethod
    def _physical_time_ms() -> int:
        return int(time.time() * 1000)
