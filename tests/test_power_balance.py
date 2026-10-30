"""Phase 1 DoD: power balance holds (generation ~= load + losses) in steady state.

Also checks the frequency proxy sits at nominal when the grid is undisturbed,
and that repeated ticks don't drift the solution.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from grid.engine import GridEngine
from grid import model


def test_power_balance_steady_state():
    engine = GridEngine(tick_hz=1.0)
    # run to steady state
    snap = None
    for _ in range(5):
        snap = engine.step()
    assert snap.converged, "steady-state power flow must converge"

    # generation = load + losses, to within numerical tolerance.
    # losses are reported as gen - load, so check gen == load + losses exactly
    # AND that losses are a small positive fraction of load (a real AC system).
    residual = snap.total_gen_mw - (snap.total_load_mw + snap.losses_mw)
    assert abs(residual) < 1e-3, f"power balance residual too large: {residual} MW"

    assert snap.losses_mw > 0, "AC losses should be positive"
    assert snap.losses_mw < 0.05 * snap.total_load_mw, "losses should be a few % of load"


def test_frequency_nominal_when_undisturbed():
    engine = GridEngine(tick_hz=1.0)
    for _ in range(5):
        snap = engine.step()
    assert abs(snap.frequency_hz - model.NOMINAL_FREQUENCY_HZ) < 1e-6, \
        "frequency proxy must sit at nominal with no disturbance"


def test_steady_state_does_not_drift():
    engine = GridEngine(tick_hz=1.0)
    first = engine.step()
    for _ in range(10):
        last = engine.step()
    assert abs(last.total_gen_mw - first.total_gen_mw) < 1e-6, \
        "undisturbed steady state must not drift tick to tick"
    assert last.max_line_loading_percent == first.max_line_loading_percent


def test_no_element_overloaded_in_base_case():
    engine = GridEngine(tick_hz=1.0)
    snap = engine.step()
    assert snap.max_line_loading_percent < 100.0, \
        "base case should be within ratings (N-0 secure)"
