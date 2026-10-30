"""Attack #6 — False Data Injection Attack (FDIA). THE one that matters.

Goal: feed the control center a measurement vector that is *wrong* about the
grid's true state, yet slips past the conventional weighted-least-squares +
chi-square bad-data test that every real EMS runs.

How the evasion works (the important part)
------------------------------------------
The chi-square test flags a measurement set z when the WLS residual is large:

        r = z - h(x̂),      J(x̂) = rᵀ R⁻¹ r,      flag if J > χ²_{α, m-n}

An attacker who adds an error vector ``a`` to the measurements (z' = z + a) stays
invisible to this test **if and only if a lies in the column space (range) of
the measurement Jacobian H = ∂h/∂x** — i.e. a = H·c for some state offset c.
Then the estimator simply shifts its solution to x̂ + c and the residual is
completely unchanged (r' = z' - h(x̂+c) ≈ z - h(x̂) = r), so J does not move.
This is the classic Liu–Ning–Reiter stealth condition.

We construct such an ``a`` **without ever touching H explicitly**: instead of
crafting a numerically, we build a genuine *alternate* power-flow solution
x_false (a different but physically valid operating point) and read its
measurements z_false = h(x_false). Because z_false satisfies Kirchhoff's laws
exactly, it is internally consistent — the estimator fits it with ~zero
residual — while encoding a state that differs from reality. Concretely
a = z_false - z_true ≈ H·(x_false - x_true), i.e. a ∈ range(H) by construction.

Why the naive test can't win, but L3 can
----------------------------------------
The residual test only knows the measurements the attacker controls, and those
are self-consistent. The one thing the attacker cannot forge is a small set of
*trusted* measurements (secured PMUs) it can't reach. Those still reflect the
true state, so cross-checking the estimator's (shifted) solution against them
exposes the lie. That trusted-subset cross-check is Phase 5 (L3). Here in
Phase 3 we only build the attack and prove the conventional test is fooled.

Target detection layer: L3 (physics) — trusted-PMU cross-validation. The naive
chi-square test is *defeated by design*.
"""
from __future__ import annotations

import copy
import warnings

import pandapower as pp

from .common import AttackResult, register, cli_main
from detect.l3_physics.estimator import (
    StateEstimator,
    measurements_from_powerflow,
)

# Buses whose measurements are held out as "trusted / secured PMU" — the
# attacker cannot reach these, and they are chosen in the disturbed corridor so
# they actually see the injected state error (that is what lets L3 catch it).
TRUSTED_BUSES = [16, 21, 22]

# The attacker's target: make the corridor around bus 15 look ~150 MW lighter
# than it truly is (a precursor to hiding a real overload from the operator).
TARGET_BUS = 15
HIDDEN_MW = 150.0


def _solved_case(net=None):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if net is None:
            import pandapower.networks as nw
            net = nw.case39()
        else:
            net = copy.deepcopy(net)
        pp.runpp(net)
    return net


def build_attack(net=None) -> dict:
    """Return the true set, the falsified reachable set, and the trusted holdout."""
    true_net = _solved_case(net)
    true_meas = measurements_from_powerflow(true_net)

    # alternate consistent state: shift load in the target corridor, re-solve.
    alt_net = copy.deepcopy(true_net)
    lo = alt_net.load.index[alt_net.load.bus == TARGET_BUS]
    if len(lo):
        alt_net.load.at[lo[0], "p_mw"] -= HIDDEN_MW
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        pp.runpp(alt_net)
    alt_meas = measurements_from_powerflow(alt_net)

    # index measurements by identity so we can splice true vs alternate values
    def key(m):
        return (m["meas_type"], m["element_type"], m["element"], m.get("side"))

    alt_by_key = {key(m): m for m in alt_meas}

    reachable, trusted = [], []
    for m in true_meas:
        k = key(m)
        is_trusted = (m["element_type"] == "bus" and m["element"] in TRUSTED_BUSES)
        if is_trusted:
            # secured measurement: attacker can't touch it -> keeps TRUE value
            trusted.append({**m, "tag": "trusted"})
        else:
            # reachable measurement: attacker overwrites with the consistent lie
            am = alt_by_key.get(k, m)
            reachable.append({**am, "tag": "reachable"})

    # Trusted nodes are secured PMUs, so they also measure voltage ANGLE (the
    # phasor part). Angle is far more sensitive to the injected state shift than
    # magnitude, so this is the strong signal L3 will cross-check in Phase 5.
    for b in TRUSTED_BUSES:
        trusted.append({"meas_type": "va", "element_type": "bus", "element": int(b),
                        "side": None, "value": float(true_net.res_bus.at[b, "va_degree"]),
                        "std": 0.02, "tag": "trusted"})

    return {
        "true_net": true_net, "alt_net": alt_net,
        "true_meas": true_meas, "reachable_meas": reachable, "trusted_meas": trusted,
    }


@register("fdia", attack_class=6, title="False Data Injection (stealthy)", layer="L3 physics")
def run(net=None) -> AttackResult:
    atk = build_attack(net)
    true_net = atk["true_net"]

    # === the conventional defence the attack is built to beat ===
    # Naive operator runs WLS + chi-square over the (compromised) reachable set.
    est = StateEstimator(true_net)
    naive = est.run(atk["reachable_meas"])

    # quantify the lie: how far the estimated state drifts from the true state
    true_va = {int(b): float(true_net.res_bus.at[b, "va_degree"]) for b in true_net.bus.index}
    max_angle_err = max(abs(naive.va_degree_est.get(b, true_va[b]) - true_va[b])
                        for b in true_va) if naive.converged else float("nan")

    # what the trusted PMUs would reveal (this is the Phase-5 catch, previewed):
    # compare each trusted measurement's TRUE value to what the estimator's
    # (attacker-shifted) solution predicts there.
    trusted_v_gap = 0.0
    trusted_angle_gap = 0.0
    for m in atk["trusted_meas"]:
        if m["meas_type"] == "v":
            est_v = naive.vm_pu_est.get(m["element"])
            if est_v is not None:
                trusted_v_gap = max(trusted_v_gap, abs(est_v - m["value"]))
        elif m["meas_type"] == "va":
            est_a = naive.va_degree_est.get(m["element"])
            if est_a is not None:
                trusted_angle_gap = max(trusted_angle_gap, abs(est_a - m["value"]))

    evaded = naive.converged and not naive.chi2_flagged

    return AttackResult(
        name="fdia",
        attack_class=6,
        title="False Data Injection Attack (stealthy, evades chi-square)",
        target_detection_layer="L3 physics (trusted-PMU cross-check); naive chi-square DEFEATED",
        executed=evaded,
        changed=[
            f"replaced the reachable SCADA measurements with a consistent alternate "
            f"power-flow state hiding ~{HIDDEN_MW:.0f} MW of load around bus {TARGET_BUS}",
            f"estimator misled by up to {max_angle_err:.2f}° of bus-angle error "
            "while reporting a clean bill of health",
            f"trusted PMUs at buses {TRUSTED_BUSES} left untouched (attacker can't reach them)",
        ],
        evidence={
            "chi2_J": round(naive.J, 3),
            "chi2_threshold": round(naive.threshold, 3),
            "chi2_flagged_bad_data": naive.chi2_flagged,      # <-- False == evaded
            "naive_test_result": "PASS (attack undetected)" if evaded else "flagged",
            "max_bus_angle_error_deg": round(max_angle_err, 3),
            "trusted_pmu_angle_gap_deg": round(trusted_angle_gap, 3),  # the Phase-5 tell (strong)
            "trusted_pmu_voltage_gap_pu": round(trusted_v_gap, 4),
            "n_reachable_meas": len(atk["reachable_meas"]),
            "n_trusted_meas": len(atk["trusted_meas"]),
        },
        why_hard_to_catch=(
            "The falsified measurements satisfy Kirchhoff's laws exactly — they are a "
            "real (alternate) power-flow solution — so the WLS residual barely moves and "
            "the chi-square test sees J well below threshold. The injected error lies in "
            "the column space of the measurement Jacobian, which is the mathematical "
            "definition of stealth against residual-based bad-data detection. No amount "
            "of tuning the chi-square threshold catches it without also rejecting good "
            "data. The only tell is the trusted-PMU subset the attacker never touched: "
            "its true readings disagree with the estimator's shifted solution — which is "
            "exactly what L3's cross-check exploits in Phase 5."
        ),
        artifacts={
            "reachable_meas": atk["reachable_meas"],
            "trusted_meas": atk["trusted_meas"],
            "true_meas": atk["true_meas"],
            "target_bus": TARGET_BUS,
            "hidden_mw": HIDDEN_MW,
            "trusted_buses": TRUSTED_BUSES,
        },
    )


if __name__ == "__main__":
    raise SystemExit(cli_main(run))
