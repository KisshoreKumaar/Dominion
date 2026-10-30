"""Grid model construction for GRIDSENTINEL.

Loads the IEEE 39-bus New England test case (`pandapower.networks.case39`)
and adds the metadata GRIDSENTINEL needs on top of it:

  * a stable notion of "breaker" per line and transformer (we model a breaker
    as the element's ``in_service`` flag — opening a breaker takes the element
    out of service, which the AC power flow then routes around),
  * per-element current ratings used by the overload-protection logic,
  * a captured "nominal" slack-bus injection used as the reference point for
    the demo frequency proxy (see grid/engine.py).

Design note — this is the *only* place that knows about pandapower table
layout. Everything downstream speaks in GridSnapshot terms (grid/state.py).
"""
from __future__ import annotations

import warnings

import pandapower as pp
import pandapower.networks as nw

# New England system runs at 60 Hz.
NOMINAL_FREQUENCY_HZ = 60.0


def load_case39():
    """Return a fresh, solved case39 network ready for the simulation loop.

    We run one power flow immediately so callers can read a consistent
    steady state (and so we can capture the nominal slack injection).
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        net = nw.case39()

    # case39 ships without explicit current ratings on some lines; pandapower's
    # loading_percent needs max_i_ka. Backfill any missing/zero ratings from the
    # element's own nominal current so protection always has a threshold.
    _ensure_line_ratings(net)

    # Solve once so res_* tables exist and we can snapshot the nominal state.
    run_power_flow(net)

    # Capture the reference slack injection for the frequency proxy. In steady
    # state the slack (ext_grid) mostly supplies losses + the gap the fixed PV
    # generators don't cover; deviation from this baseline is our freq signal.
    net["_gs_slack_p_nominal_mw"] = float(net.res_ext_grid.p_mw.sum())
    net["_gs_slack_bus"] = int(net.ext_grid.bus.iloc[0])
    return net


def _ensure_line_ratings(net) -> None:
    """Guarantee every line/trafo has a usable rating for overload checks."""
    # Lines: max_i_ka must be > 0 for loading_percent to be meaningful.
    for idx in net.line.index:
        max_i = net.line.at[idx, "max_i_ka"]
        if not max_i or max_i <= 0:
            # Fall back to a generous default so a missing rating never causes
            # a spurious permanent overload. 1.0 kA is conservative for 345 kV.
            net.line.at[idx, "max_i_ka"] = 1.0
    # Give trafos a max_loading if absent (defaults to 100% otherwise).
    if "max_loading_percent" not in net.trafo.columns:
        net.trafo["max_loading_percent"] = 100.0
    if "max_loading_percent" not in net.line.columns:
        net.line["max_loading_percent"] = 100.0


def run_power_flow(net) -> bool:
    """Run AC power flow. Returns convergence flag; never raises on divergence.

    Fail-open contract (Section 1): a non-converging solve must not crash the
    caller. We report converged=False and let the engine hold the last good
    state.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            pp.runpp(net, numba=False, calculate_voltage_angles=True)
        return bool(net.converged)
    except Exception:
        # Divergence / singular matrix / islanded network after a trip.
        return False


def worst_n1_line(net) -> tuple[int, float]:
    """Find the single in-service line whose outage most stresses the rest of
    the network (highest resulting loading on any surviving line), while still
    serving essentially all load (i.e. not just islanding a load pocket).

    Used by the trip test to pick an outage that produces an *emergent*
    cascade rather than a benign redistribution — the interesting demo case.
    Returns (line_id, resulting_max_loading_percent).
    """
    import copy

    base_load = float(net.res_load.p_mw.sum()) if len(net.res_load) else float(net.load.p_mw.sum())
    best_idx = None
    best_loading = -1.0
    for idx in net.line.index:
        if not bool(net.line.at[idx, "in_service"]):
            continue
        trial = copy.deepcopy(net)
        trial.line.at[idx, "in_service"] = False
        if not run_power_flow(trial):
            continue
        served = float(trial.res_load.p_mw.sum())
        # Skip outages that mostly just shed load by islanding (>2% load lost).
        if served < 0.98 * base_load:
            continue
        surviving = trial.line[trial.line.in_service].index
        max_loading = float(trial.res_line.loading_percent[surviving].max())
        if max_loading > best_loading:
            best_loading = max_loading
            best_idx = int(idx)
    return best_idx, best_loading


def breaker_controlled_lines(net) -> list[int]:
    """Line indices that carry a controllable breaker (all of them here)."""
    return list(net.line.index)


def breaker_controlled_trafos(net) -> list[int]:
    return list(net.trafo.index)
