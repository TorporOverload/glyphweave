from app.core.domain.sync.hlc import HLCClock, compare_hlc, hlc_to_tuple, is_hlc_after, is_hlc_before
from app.core.domain.sync.models import HybridLogicalClock


def test_hlc_clock_observe_remote_time_in_past(monkeypatch) -> None:
    """Clock observe with remote time in the past keeps local logical advancing."""
    monkeypatch.setattr("app.core.domain.sync.hlc.time.time", lambda: 5.0)
    clock = HLCClock(device_id="device-a", wall_time=5000, logical=3)

    observed = clock.observe(
        {"wall_time": 1000, "logical": 999, "device_id": "device-b"}
    )

    assert observed == (5000, 4, "device-a")


def test_hlc_clock_observe_remote_logical_in_past(monkeypatch) -> None:
    """Clock observe with remote logical in past but wall_time equal advances local logical."""
    monkeypatch.setattr("app.core.domain.sync.hlc.time.time", lambda: 3.0)
    clock = HLCClock(device_id="device-a", wall_time=3000, logical=2)

    observed = clock.observe(
        {"wall_time": 3000, "logical": 1, "device_id": "device-b"}
    )

    assert observed == (3000, 3, "device-a")


def test_hlc_equality_different_device_ids() -> None:
    """HLCs with same wall and logical but different device IDs are not equal."""
    hlc1 = HybridLogicalClock(wall_time=1000, logical=5, device_id="device-a")
    hlc2 = HybridLogicalClock(wall_time=1000, logical=5, device_id="device-b")

    assert hlc1 != hlc2
    assert hlc1.to_dict() != hlc2.to_dict()


def test_hlc_serialization_roundtrip_preserves_values() -> None:
    """HybridLogicalClock serializes and deserializes preserving all values."""
    original = HybridLogicalClock(wall_time=1234567890, logical=42, device_id="test-device")

    serialized = original.to_dict()
    restored = HybridLogicalClock.from_dict(serialized)

    assert restored == original
    assert restored.wall_time == 1234567890
    assert restored.logical == 42
    assert restored.device_id == "test-device"


def test_hlc_serialization_with_zero_wall_time() -> None:
    """HLC with zero wall_time serializes and deserializes correctly."""
    hlc = HybridLogicalClock(wall_time=0, logical=0, device_id="zero-device")

    restored = HybridLogicalClock.from_dict(hlc.to_dict())

    assert restored.wall_time == 0
    assert restored.logical == 0
    assert restored.device_id == "zero-device"


def test_hlc_serialization_with_large_logical() -> None:
    """HLC with very large logical value serializes and deserializes correctly."""
    hlc = HybridLogicalClock(wall_time=1000000, logical=999999999999, device_id="large-logical")

    restored = HybridLogicalClock.from_dict(hlc.to_dict())

    assert restored.logical == 999999999999


def test_hlc_serialization_from_dict_converts_types() -> None:
    """from_dict converts string numeric values to integers."""
    data = {"wall_time": "1000", "logical": "5", "device_id": "test"}
    hlc = HybridLogicalClock.from_dict(data)

    assert hlc.wall_time == 1000
    assert hlc.logical == 5


def test_hlc_compare_same_wall_different_logical() -> None:
    """Comparison: same wall_time, higher logical wins."""
    lower = {"wall_time": 1000, "logical": 1, "device_id": "a"}
    higher = {"wall_time": 1000, "logical": 2, "device_id": "a"}

    assert compare_hlc(lower, higher) == -1
    assert compare_hlc(higher, lower) == 1


def test_hlc_compare_same_values_different_devices() -> None:
    """Comparison: same wall_time and logical, device_id is tiebreaker."""
    a = {"wall_time": 1000, "logical": 5, "device_id": "aaa"}
    b = {"wall_time": 1000, "logical": 5, "device_id": "bbb"}

    assert compare_hlc(a, b) == -1
    assert compare_hlc(b, a) == 1


def test_hlc_compare_zero_values() -> None:
    """Comparison works with all zero values."""
    zero_a = {"wall_time": 0, "logical": 0, "device_id": "a"}
    zero_b = {"wall_time": 0, "logical": 0, "device_id": "b"}

    assert compare_hlc(zero_a, zero_b) == -1
    assert compare_hlc(zero_b, zero_a) == 1


def test_hlc_is_after_boundary_same_values() -> None:
    """is_after returns False for identical HLCs."""
    hlc = {"wall_time": 1000, "logical": 5, "device_id": "a"}

    assert is_hlc_after(hlc, hlc) is False


def test_hlc_is_before_boundary_same_values() -> None:
    """is_before returns False for identical HLCs."""
    hlc = {"wall_time": 1000, "logical": 5, "device_id": "a"}

    assert is_hlc_before(hlc, hlc) is False


def test_hlc_clock_next_returns_increasing_values(monkeypatch) -> None:
    """Multiple next() calls on clock return increasing logical values."""
    monkeypatch.setattr("app.core.domain.sync.hlc.time.time", lambda: 1.0)
    clock = HLCClock(device_id="test")

    first = clock.next()
    second = clock.next()
    third = clock.next()

    assert first[1] < second[1] < third[1]


def test_hlc_clock_to_hlc_contains_all_fields() -> None:
    """HLCClock.to_hlc returns all three required fields."""
    clock = HLCClock(device_id="test-device", wall_time=5000, logical=10)

    result = clock.to_hlc()

    assert result["wall_time"] == 5000
    assert result["logical"] == 10
    assert result["device_id"] == "test-device"


def test_hlc_tuple_conversion_from_dict() -> None:
    """hlc_to_tuple works with dict inputs."""
    hlc_dict = {"wall_time": 1000, "logical": 5, "device_id": "test"}
    result = hlc_to_tuple(hlc_dict)

    assert result == (1000, 5, "test")


def test_hlc_clock_observe_with_future_remote_wall(monkeypatch) -> None:
    """Clock observe with remote wall_time in future sets logical to 0."""
    monkeypatch.setattr("app.core.domain.sync.hlc.time.time", lambda: 1.0)
    clock = HLCClock(device_id="device-a", wall_time=1000, logical=5)

    observed = clock.observe(
        {"wall_time": 2000, "logical": 100, "device_id": "device-b"}
    )

    assert observed[0] == 2000
    assert observed[1] == 0


def test_hlc_clock_observe_local_wall_ahead(monkeypatch) -> None:
    """When local wall_time is ahead, logical increments."""
    monkeypatch.setattr("app.core.domain.sync.hlc.time.time", lambda: 1.0)
    clock = HLCClock(device_id="device-a", wall_time=5000, logical=3)

    observed = clock.observe(
        {"wall_time": 3000, "logical": 999, "device_id": "device-b"}
    )

    assert observed == (5000, 4, "device-a")


def test_hlc_clock_next_with_wall_time_advance(monkeypatch) -> None:
    """next() returns higher wall_time when physical time advances between calls."""
    monkeypatch.setattr("app.core.domain.sync.hlc.time.time", lambda: 1.0)
    clock = HLCClock(device_id="test")

    first = clock.next()

    monkeypatch.setattr("app.core.domain.sync.hlc.time.time", lambda: 2.0)
    second = clock.next()

    assert first[0] == 1000
    assert second[0] == 2000
    assert second[1] == 0