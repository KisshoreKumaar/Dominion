"""Phase 1 DoD: a manual trip produces a believable local cascade, not a crash
or a no-op, and the fail-open contract holds.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from grid.engine import GridEngine
from grid import model
from grid.protection import OverloadProtection


def test_manual_trip_redistributes_and_survives():
    engine = GridEngine(tick_hz=1.0, pickup_ticks=3)
    for _ in range(3):
        engine.step()
    before = engine.snapshot
    before_max = before.max_line_loading_percent

    # trip the most cascade-prone line
    target, _ = model.worst_n1_line(engine.net)
    assert target is not None
    engine.trip_line(target)

    for _ in range(10):
        engine.step()
    after = engine.snapshot

    assert after.converged, "grid must still solve after a trip (no crash)"
    assert target in after.tripped_lines(), "the tripped line must be open"
    # not a no-op: loading distribution changed
    assert abs(after.max_line_loading_percent - before_max) > 0.01


def test_emergent_cascade_occurs():
    """Tripping the worst N-1 outage should trip additional elements via the
    protection logic (a cascade), not just the one we opened."""
    engine = GridEngine(tick_hz=1.0, pickup_ticks=3)
    for _ in range(3):
        engine.step()
    target, _ = model.worst_n1_line(engine.net)
    engine.trip_line(target)
    for _ in range(10):
        engine.step()
    tripped = engine.snapshot.tripped_lines()
    assert len(tripped) >= 2, f"expected an emergent cascade, only tripped {tripped}"


def test_protection_needs_consecutive_ticks():
    """A one-tick blip below threshold must reset the counter (no spurious trip)."""
    prot = OverloadProtection(pickup_ticks=3, threshold_percent=100.0)
    key = ("line", 5)
    prot.evaluate({key: 120.0})   # 1
    prot.evaluate({key: 120.0})   # 2
    trips = prot.evaluate({key: 50.0})  # reset
    assert trips == []
    assert prot.counters_snapshot().get("line:5", 0) == 0
    # now build back up: needs 3 more consecutive
    prot.evaluate({key: 120.0})
    prot.evaluate({key: 120.0})
    trips = prot.evaluate({key: 120.0})
    assert trips and trips[0][0:2] == ("line", 5)


def test_fail_open_on_broken_subscriber():
    """A subscriber that raises must not break the grid loop (fail-open)."""
    engine = GridEngine(tick_hz=1.0)

    def bad_subscriber(_snap):
        raise RuntimeError("subscriber blew up")

    engine.subscribe(bad_subscriber)
    snap = engine.step()  # should not raise
    assert snap.converged


def test_reserve_margin_present():
    engine = GridEngine(tick_hz=1.0)
    snap = engine.step()
    assert snap.reserve_margin_mw >= 0.0
