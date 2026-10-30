"""Phase 5 DoD tests: L2 (protocol) + L3 (physics) catch attacks 4-7.

The single most important test in the project is test_fdia_naive_passes_but_L3_catches:
the conventional chi-square test PASSES (attack succeeds against naive detection)
while the full L3 trusted-subset cross-check CATCHES it (attack fails against L3).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detect.events import EventStore
from detect import pipeline
from detect.l3_physics.detector import TrustedSubsetMonitor
from attacks import fdia as fdia_mod


# ================= THE proof point =================

def test_fdia_naive_passes_but_L3_catches():
    """Contrast test: naive chi-square is fooled; trusted-subset cross-check wins."""
    atk = fdia_mod.build_attack()
    monitor = TrustedSubsetMonitor(atk["true_net"], angle_threshold_deg=1.0)
    res = monitor.check(atk["reachable_meas"], atk["trusted_meas"])

    # 1) the conventional chi-square test PASSES (attack succeeds against it)
    assert res.naive_chi2_flagged is False, (
        f"naive chi-square should be fooled (J={res.naive_J:.2f} < {res.naive_threshold:.2f})")
    assert res.naive_J < res.naive_threshold

    # 2) the full L3 trusted-subset check CATCHES it (attack fails against L3)
    assert res.fdia_detected is True, "trusted-PMU cross-check must catch the FDIA"
    assert res.max_angle_gap_deg > 1.0
    assert res.event is not None and res.event.severity == "critical"
    # the event explains the contrast (explainable verdict)
    assert "chi-square PASSED" in res.event.reason
    assert "trusted" in res.event.reason.lower()


def test_fdia_detection_latency_recorded():
    store = EventStore()
    r = pipeline.run_l3_fdia(store)
    assert r["detection_latency_cycles"] == 1
    assert r["detection_wall_ms"] > 0
    assert not r["naive_chi2_flagged"] and r["fdia_detected_by_trusted_subset"]


# ================= L2 protocol (attacks 4, 5) =================

def test_l2_catches_replay_and_setpoint_no_fp():
    store = EventStore()
    r = pipeline.run_l2_protocol(store)
    dets = set(r["by_detector"].keys())
    # replay (#4): caught by authorization and by the replay signature
    assert "L2.protocol.replay" in dets
    assert any(e.evidence.get("src") == "replay-bot"
               for evs in r["by_detector"].values() for e in evs)
    # setpoint (#5): caught by write-rate ceiling and authorization
    assert "L2.protocol.write_rate" in dets
    assert any(e.evidence.get("src") == "setpoint-injector"
               for evs in r["by_detector"].values() for e in evs)
    # legitimate traffic produced no false positives
    assert len(r["false_positives"]) == 0
    assert r["masters"] == ["control-center"]


# ================= L3 HMI blinding (attack 7) =================

def test_l3_catches_hmi_blinding_no_fp():
    store = EventStore()
    r = pipeline.run_l3_hmi(store)
    assert len(r["flagged"]) >= 1, "HMI blinding must be caught by consistency check"
    ev = r["flagged"][0]
    assert ev.layer == "L3"
    assert "breaker_flow" in ev.detector
    # a healthy (unmanipulated) view produced no false positives
    assert len(r["false_positives"]) == 0


# ================= events land in the shared store =================

def test_l2_l3_events_share_the_store():
    store = EventStore()
    pipeline.run_l2_protocol(store)
    pipeline.run_l3_hmi(store)
    pipeline.run_l3_fdia(store)
    assert len(store.events(layer="L2")) >= 1
    assert len(store.events(layer="L3")) >= 2   # HMI + FDIA
    # the FDIA event is the highest severity in the store
    crit = store.events(min_severity="critical")
    assert any(e.detector == "L3.physics.trusted_pmu" for e in crit)
