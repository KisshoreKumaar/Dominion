"""Phase 3 DoD tests for the attack harness.

The headline test is FDIA vs the conventional chi-square check: the naive test
must PASS (i.e. the attack succeeds against naive detection). This is the
baseline Phase 5's L3 has to beat.

The SCADA-backed attacks (boundary/replay/setpoint/hmi_blind) each stand up a
real RTU farm, so they are grouped under a single module-scoped system to avoid
rebinding ports per test.
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attacks import harness
from attacks import fdia as fdia_mod
from detect.l3_physics.estimator import StateEstimator


# ---------------- standalone attacks (no SCADA needed) ----------------

def test_registry_has_all_seven():
    names = [a["name"] for a in harness.list_attacks()]
    assert names == ["phishing", "malware", "boundary", "replay", "setpoint", "fdia", "hmi_blind"]
    classes = sorted(a["class"] for a in harness.list_attacks())
    assert classes == [1, 2, 3, 4, 5, 6, 7]


def test_phishing_executes_and_flags_features():
    r = harness.run_attack("phishing")
    assert r.executed
    f = r.artifacts["email_sample"]["features"]
    assert f["attachment_has_macro"] and f["reply_to_mismatch"] and not f["spf_pass"]


def test_malware_signal_is_suspicious():
    r = harness.run_attack("malware")
    assert r.executed
    sig = r.artifacts["endpoint_signal"]
    assert sig["features"]["office_spawned_shell"]
    assert sig["features"]["num_suspicious_pairs"] >= 2
    # beacon timing is machine-regular (low stdev relative to mean)
    f = sig["features"]
    assert f["beacon_interval_stdev_s"] < 0.25 * f["beacon_mean_interval_s"]


# ---------------- FDIA: the core proof point ----------------

def test_fdia_evades_conventional_chi2():
    """DoD: a conventional WLS + chi-square check must PASS on the FDIA-crafted
    measurements — i.e. the attack succeeds against naive detection."""
    atk = fdia_mod.build_attack()
    est = StateEstimator(atk["true_net"])
    naive = est.run(atk["reachable_meas"])

    assert naive.converged, "state estimation should converge on the crafted set"
    # THE assertion: chi-square does NOT flag the attack (naive detector fooled)
    assert not naive.chi2_flagged, (
        f"naive chi-square unexpectedly flagged the FDIA "
        f"(J={naive.J:.2f}, thr={naive.threshold:.2f})")
    assert naive.J < naive.threshold


def test_fdia_actually_corrupts_the_state_estimate():
    """The attack must meaningfully move the estimate, else 'evasion' is trivial."""
    atk = fdia_mod.build_attack()
    est = StateEstimator(atk["true_net"])
    naive = est.run(atk["reachable_meas"])
    true_va = {int(b): float(atk["true_net"].res_bus.at[b, "va_degree"])
               for b in atk["true_net"].bus.index}
    max_err = max(abs(naive.va_degree_est[b] - true_va[b]) for b in true_va)
    assert max_err > 1.0, f"FDIA barely moved the estimate ({max_err:.2f} deg)"


def test_fdia_trusted_subset_reveals_the_lie():
    """Preview of the Phase-5 catch: the untouched trusted PMUs disagree with the
    estimator's shifted solution (the signal L3 will use)."""
    atk = fdia_mod.build_attack()
    est = StateEstimator(atk["true_net"])
    naive = est.run(atk["reachable_meas"])
    gap = 0.0
    for m in atk["trusted_meas"]:
        if m["meas_type"] == "va":
            gap = max(gap, abs(naive.va_degree_est[m["element"]] - m["value"]))
    assert gap > 1.0, "trusted PMU angle gap should expose the injected state error"


# ---------------- SCADA-backed attacks ----------------

@pytest.fixture(scope="module")
def scada():
    from scada.scada_system import ScadaSystem
    from scada.capture import CaptureBus
    cap = CaptureBus()
    sysm = ScadaSystem(capture=cap, tick_hz=8.0)
    sysm.start()
    time.sleep(1.0)
    yield sysm
    sysm.stop()
    time.sleep(0.3)


def test_boundary_opens_novel_session(scada):
    r = harness.run_attack("boundary", system=scada)
    assert r.executed
    # a capture event from the novel source must exist
    evs = [e for e in scada.capture.events(capture_point="client")
           if e.src == "compromised-eng-laptop"]
    assert evs, "boundary attack should appear on the capture bus from a novel source"


def test_replay_reopens_breaker_from_attacker_session(scada):
    # make sure line 26 starts closed
    scada.control.operate_breaker("rtu-21", 26, close=True)
    time.sleep(0.5)
    r = harness.run_attack("replay", system=scada)
    assert r.executed, "replayed frame should have re-opened the breaker"
    assert r.evidence["replay_matches_recorded"]
    scada.control.operate_breaker("rtu-21", 26, close=True)
    time.sleep(0.5)


def test_setpoint_burst_moves_generator(scada):
    orig_mw = float(scada.engine.net.gen.at[2, "p_mw"])
    r = harness.run_attack("setpoint", system=scada, target_mw=60.0, burst=5)
    assert r.executed
    assert r.evidence["write_rate_per_s"] > 5.0
    assert abs(r.evidence["setpoint_after_mw"] - 60.0) < 5.0
    # restore the generator so we don't leave the grid generation-deficient
    scada.control.set_generator_setpoint("rtu-32", orig_mw)
    time.sleep(0.6)


def test_hmi_blinding_desyncs_view_from_reality(scada):
    r = harness.run_attack("hmi_blind", system=scada, divert_line=26)
    assert r.executed
    # operator sees CLOSED, reality is OPEN
    assert r.evidence["reported_breaker_closed"] is True
    assert r.evidence["real_breaker_closed"] is False
    # restore grid for cleanliness
    scada.control.operate_breaker("rtu-21", 26, close=True)
    time.sleep(0.5)
