from app.core.domain.sync.hlc import HLCClock, compare_hlc, hlc_to_tuple, is_hlc_after, is_hlc_before
from app.core.domain.sync.models import HybridLogicalClock


def test_hlc_to_tuple_accepts_mapping() -> None:
    hlc = {"wall_time": 1000, "logical": 2, "device_id": "a"}

    assert hlc_to_tuple(hlc) == (1000, 2, "a")


def test_compare_hlc_orders_by_wall_time_then_logical_then_device_id() -> None:
    early = {"wall_time": 1000, "logical": 0, "device_id": "b"}
    logical_later = {"wall_time": 1000, "logical": 1, "device_id": "a"}
    wall_later = {"wall_time": 1001, "logical": 0, "device_id": "a"}

    assert compare_hlc(early, logical_later) == -1
    assert compare_hlc(logical_later, wall_later) == -1
    assert compare_hlc(wall_later, early) == 1


def test_compare_hlc_uses_device_id_as_final_tiebreaker() -> None:
    a = {"wall_time": 1000, "logical": 0, "device_id": "device-a"}
    b = {"wall_time": 1000, "logical": 0, "device_id": "device-b"}

    assert compare_hlc(a, b) == -1
    assert compare_hlc(b, a) == 1


def test_is_hlc_after_and_before() -> None:
    earlier = {"wall_time": 1000, "logical": 0, "device_id": "a"}
    later = {"wall_time": 1000, "logical": 1, "device_id": "a"}

    assert is_hlc_after(later, earlier) is True
    assert is_hlc_before(earlier, later) is True
    assert is_hlc_after(earlier, later) is False
    assert is_hlc_before(later, earlier) is False


def test_hybrid_logical_clock_round_trips() -> None:
    hlc = HybridLogicalClock(wall_time=1736505045000, logical=3, device_id="test")

    restored = HybridLogicalClock.from_dict(hlc.to_dict())

    assert restored == hlc


def test_hlc_clock_observe_remote_future_advances_logical(monkeypatch) -> None:
    monkeypatch.setattr("app.core.domain.sync.hlc.time.time", lambda: 1.0)
    clock = HLCClock(device_id="device-a")

    observed = clock.observe(
        {"wall_time": 2000, "logical": 4, "device_id": "device-b"}
    )
    emitted = clock.next()

    assert observed == (2000, 5, "device-a")
    assert emitted == (2000, 6, "device-a")


def test_hlc_clock_observe_equal_wall_uses_max_logical_plus_one(monkeypatch) -> None:
    monkeypatch.setattr("app.core.domain.sync.hlc.time.time", lambda: 3.0)
    clock = HLCClock(device_id="device-a", wall_time=3000, logical=2)

    observed = clock.observe(
        {"wall_time": 3000, "logical": 5, "device_id": "device-b"}
    )

    assert observed == (3000, 6, "device-a")

