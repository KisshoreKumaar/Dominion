"""Weighted-least-squares state estimation + chi-square residual test.

This is the *conventional* physics baseline: exactly the bad-data test a real
control center runs, and exactly what the FDIA (attack #6) is built to evade.
Phase 3 uses it to prove the attack slips past chi-square; Phase 5 (L3) extends
this module with the trusted-PMU cross-check and breaker/topology checks that
actually catch the attack.

A "measurement set" is a list of plain dicts so it can be crafted, falsified,
sliced into trusted/untrusted subsets, and serialised to JSON without dragging
a pandapower net around:

    {"meas_type": "v"|"p"|"q"|"i", "element_type": "bus"|"line"|"trafo",
     "element": <idx>, "side": "from"|"to"|None, "value": <float>, "std": <float>,
     "tag": <optional str, e.g. "trusted">}
"""
from __future__ import annotations

import warnings
from dataclasses import dataclass

import numpy as np
import pandapower as pp
from scipy.stats import chi2 as _chi2dist

from pandapower.estimation.state_estimation import StateEstimation, _initialize_voltage


# default measurement standard deviations (SCADA-grade)
STD_V = 0.004      # pu on voltage magnitude
STD_P = 4.0        # MW on active power
STD_Q = 4.0        # Mvar on reactive power


def measurements_from_powerflow(net, include_lines: bool = True) -> list[dict]:
    """Harvest a full measurement set from a *solved* network (res_* tables).

    Produces bus voltage magnitudes, bus P/Q injections, and line P/Q flows —
    the standard redundant SCADA measurement set for state estimation.
    """
    meas: list[dict] = []
    for b in net.bus.index:
        meas.append({"meas_type": "v", "element_type": "bus", "element": int(b),
                     "side": None, "value": float(net.res_bus.at[b, "vm_pu"]), "std": STD_V})
        meas.append({"meas_type": "p", "element_type": "bus", "element": int(b),
                     "side": None, "value": float(net.res_bus.at[b, "p_mw"]), "std": STD_P})
        meas.append({"meas_type": "q", "element_type": "bus", "element": int(b),
                     "side": None, "value": float(net.res_bus.at[b, "q_mvar"]), "std": STD_Q})
    if include_lines:
        for l in net.line.index:
            if not bool(net.line.at[l, "in_service"]):
                continue
            meas.append({"meas_type": "p", "element_type": "line", "element": int(l),
                         "side": "from", "value": float(net.res_line.at[l, "p_from_mw"]), "std": STD_P})
            meas.append({"meas_type": "q", "element_type": "line", "element": int(l),
                         "side": "from", "value": float(net.res_line.at[l, "q_from_mvar"]), "std": STD_Q})
    return meas


def apply_measurements(net, meas: list[dict]) -> None:
    """Replace the net's measurement table with the given measurement set."""
    if len(net.measurement):
        net.measurement.drop(net.measurement.index, inplace=True)
    for m in meas:
        pp.create_measurement(net, m["meas_type"], m["element_type"], m["value"],
                              m["std"], element=m["element"], side=m.get("side"))


@dataclass
class SEResult:
    converged: bool
    J: float                # chi-square performance index  r^T R^-1 r
    threshold: float        # chi2.ppf(1-alpha, m-n)
    n_meas: int
    n_state: int
    chi2_flagged: bool      # True => conventional test says "bad data"
    vm_pu_est: dict         # bus_id -> estimated voltage magnitude
    va_degree_est: dict     # bus_id -> estimated voltage angle


class StateEstimator:
    """Runs WLS SE + chi-square on a measurement set against a network topology."""

    def __init__(self, net, chi2_alpha: float = 0.05):
        # work on a copy so estimation never disturbs the caller's net/grid
        self.net = _copy_topology(net)
        self.alpha = chi2_alpha

    def run(self, meas: list[dict]) -> SEResult:
        net = self.net
        apply_measurements(net, meas)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            se = StateEstimation(net, 1e-6, 30, algorithm="wls")
            v0, d0 = _initialize_voltage(net, "flat")
            try:
                se.estimate(v0, d0)
                converged = bool(se.solver.successful)
            except Exception:
                converged = False
            if not converged:
                return SEResult(False, float("inf"), 0.0, len(meas), 0, True, {}, {})

            r = np.asarray(se.solver.r).ravel()
            R_inv = se.solver.R_inv
            J = float(np.asarray(r @ (R_inv @ r)).ravel()[0])
            m = len(net.measurement)
            n = len(se.solver.eppci.v) + len(se.solver.eppci.delta) - 1
            threshold = float(_chi2dist.ppf(1 - self.alpha, max(m - n, 1)))
            vm = {int(b): float(net.res_bus_est.at[b, "vm_pu"]) for b in net.bus.index}
            va = {int(b): float(net.res_bus_est.at[b, "va_degree"]) for b in net.bus.index}
            return SEResult(True, J, threshold, m, n, J > threshold, vm, va)


def _copy_topology(net):
    import copy
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        c = copy.deepcopy(net)
    if len(c.measurement):
        c.measurement.drop(c.measurement.index, inplace=True)
    return c
