"""Phase 4 detection pipeline — wire attacks 1-3 to L0/L1 detectors.

Each ``run_*`` runs the relevant attack (or reuses a supplied system), feeds its
artifact/traffic to the detector, emits any DetectionEvent to the shared store,
and returns the event(s). ``false_positive_check`` runs legitimate inputs and
asserts they stay below threshold.
"""
from __future__ import annotations

import time
from typing import Optional

from .events import EventStore, get_event_store
from .l0_entry.mail import MailClassifier, benign_email_sample
from .l0_entry.endpoint import EndpointDetector, benign_endpoint_signal
from .l1_boundary.boundary import BoundaryBaseline, BoundaryDetector
from .l2_protocol.protocol import ProtocolBaseline, ProtocolDetector
from .l3_physics.detector import TrustedSubsetMonitor, ConsistencyMonitor


def run_l0_mail(store: Optional[EventStore] = None):
    from attacks.phishing import phishing_sample
    store = store if store is not None else get_event_store()
    clf = MailClassifier()
    ev = clf.detect({"raw": phishing_sample()["raw"], "features": phishing_sample()["features"]})
    if ev:
        store.emit(ev)
    return ev


def run_l0_endpoint(store: Optional[EventStore] = None):
    from attacks.malware import build_signal
    store = store if store is not None else get_event_store()
    det = EndpointDetector()
    ev = det.detect(build_signal())
    if ev:
        store.emit(ev)
    return ev


def run_l1_boundary(store: Optional[EventStore] = None, system=None):
    """Learn a boundary baseline from legitimate control-center traffic, then run
    attack #3 and flag the novel session."""
    from attacks import harness
    from attacks.common import live_scada

    store = store if store is not None else get_event_store()
    with live_scada(system) as sysm:
        cap = sysm.capture
        cap.clear()

        # 1) generate legitimate boundary traffic (the control center polling)
        for _ in range(3):
            sysm.control.poll_all()
            time.sleep(0.1)
        legit_events = list(cap.events(capture_point="client"))

        # 2) learn the baseline from ONLY the legitimate traffic
        baseline = BoundaryBaseline().learn(legit_events)
        detector = BoundaryDetector(baseline)

        # 3) baseline sanity: legit traffic must NOT trip the detector (FP check)
        fp = detector.detect(legit_events)

        # 4) run the boundary attack on the same system, then scan everything
        harness.run_attack("boundary", system=sysm)
        all_events = list(cap.events(capture_point="client"))
        flagged = detector.detect(all_events, emit_to=store)

    return {"flagged": flagged, "false_positives": fp,
            "n_baseline_events": len(legit_events), "baseline": baseline}


def run_l2_protocol(store: Optional[EventStore] = None, system=None) -> dict:
    """Learn a protocol baseline from legitimate SCADA traffic, then run the
    replay (#4) and setpoint (#5) attacks and flag the protocol abuse."""
    from attacks import harness
    from attacks.common import live_scada

    store = store if store is not None else get_event_store()
    with live_scada(system) as sysm:
        cap = sysm.capture
        cap.clear()

        # 1) legitimate traffic: polls + a couple of legit operator writes so the
        #    baseline learns the master identity, the FC allowlist and the rate.
        for _ in range(2):
            sysm.control.poll_all()
        # legit operator writes across the RTUs the attacks will target, so the
        # baseline learns FC5 on rtu-21 and FC6 on rtu-32 as in-policy master ops.
        # Spaced out, as a real operator would issue them (keeps the rate ceiling low).
        for rtu, line, close in [("rtu-15", 20, False), ("rtu-15", 20, True),
                                 ("rtu-21", 26, False), ("rtu-21", 26, True)]:
            sysm.control.operate_breaker(rtu, line, close=close)
            time.sleep(0.3)
        sysm.control.set_generator_setpoint("rtu-32", 600.0)
        time.sleep(0.3)
        legit = list(cap.events(capture_point="client"))
        baseline = ProtocolBaseline().learn(legit)
        detector = ProtocolDetector(baseline)

        # false-positive check: legit traffic alone must not trip the detector
        fp = detector.detect(legit)

        # 2) run the two protocol attacks on the same system
        sysm.engine.restore_base()
        time.sleep(0.3)
        harness.run_attack("replay", system=sysm)
        harness.run_attack("setpoint", system=sysm, target_mw=50.0, burst=6)

        all_events = list(cap.events(capture_point="client"))
        flagged = detector.detect(all_events, emit_to=store)
        sysm.engine.restore_base()

    by_detector = {}
    for ev in flagged:
        by_detector.setdefault(ev.detector, []).append(ev)
    return {"flagged": flagged, "false_positives": fp, "by_detector": by_detector,
            "n_baseline_events": len(legit), "masters": sorted(baseline.masters),
            "rate_ceiling": detector.rate_ceiling}


def run_l3_fdia(store: Optional[EventStore] = None) -> dict:
    """The headline: confirm the FDIA evades naive chi-square, but the trusted-PMU
    cross-check catches it. Also measure detection latency."""
    from attacks import fdia as fdia_mod

    store = store if store is not None else get_event_store()
    atk = fdia_mod.build_attack()
    monitor = TrustedSubsetMonitor(atk["true_net"])

    # detection latency: L3 runs every measurement cycle; the FDIA is present from
    # the first cycle, so we time how long the trusted-subset check takes and
    # report the cycle count to detection (=1).
    t0 = time.perf_counter()
    result = monitor.check(atk["reachable_meas"], atk["trusted_meas"], emit_to=store)
    wall_ms = (time.perf_counter() - t0) * 1000.0

    return {
        "result": result,
        "event": result.event,
        "naive_chi2_flagged": result.naive_chi2_flagged,   # False => naive fooled
        "naive_J": round(result.naive_J, 3),
        "naive_threshold": round(result.naive_threshold, 3),
        "fdia_detected_by_trusted_subset": result.fdia_detected,
        "trusted_angle_gap_deg": result.max_angle_gap_deg,
        "detection_latency_cycles": 1 if result.fdia_detected else None,
        "detection_wall_ms": round(wall_ms, 1),
    }


def run_l3_hmi(store: Optional[EventStore] = None, system=None) -> dict:
    """Run the HMI-blinding attack (#7), leave the RTUs frozen, poll the corrupted
    view, and catch the manipulation via breaker/flow consistency."""
    from attacks import harness
    from attacks.common import live_scada

    store = store if store is not None else get_event_store()
    with live_scada(system) as sysm:
        # baseline consistency check on a healthy view (false-positive control)
        sysm.engine.restore_base()
        time.sleep(0.6)
        healthy_view = sysm.control.poll_all()
        monitor = ConsistencyMonitor()
        fp = monitor.check_view(healthy_view)

        # run the attack but keep the view frozen so L3 can inspect it
        harness.run_attack("hmi_blind", system=sysm, divert_line=26, leave_frozen=True)
        corrupted_view = sysm.control.poll_all()
        flagged = monitor.check_view(corrupted_view, emit_to=store)

        # clean up: unfreeze + restore
        for r in ("rtu-20", "rtu-21"):
            sysm.farm.set_frozen(r, False)
        sysm.engine.restore_base()

    return {"flagged": flagged, "false_positives": fp}


def false_positive_check(store: Optional[EventStore] = None) -> dict:
    """Run legitimate L0 inputs; none should produce an event above threshold."""
    clf = MailClassifier()
    mail_ev = clf.detect(benign_email_sample())
    det = EndpointDetector()
    endpoint_ev = det.detect(benign_endpoint_signal())
    return {
        "benign_mail_flagged": mail_ev is not None,
        "benign_mail_score": round(clf.score(benign_email_sample()["features"]), 3),
        "benign_endpoint_flagged": endpoint_ev is not None,
    }


def run_all(store: Optional[EventStore] = None) -> dict:
    store = store if store is not None else get_event_store()
    return {
        "L0_mail": run_l0_mail(store),
        "L0_endpoint": run_l0_endpoint(store),
        "L1_boundary": run_l1_boundary(store),
        "fp_check": false_positive_check(store),
    }
