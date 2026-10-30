"""Phase 4 demonstration: run attacks 1-3 through the L0/L1 detectors and show
one detection event per attack class, plus a legitimate-traffic FP spot-check.
"""
from __future__ import annotations

import json

from .events import EventStore
from . import pipeline


def _show(title: str, ev):
    print("\n" + "=" * 92)
    print(title)
    print("=" * 92)
    if ev is None:
        print("  !! NO DETECTION EVENT PRODUCED (this is a failure for the DoD)")
        return
    print("  " + ev.one_line())
    print(f"  stage    : {ev.attack_stage}")
    print(f"  reason   : {ev.reason}")
    print(f"  entities : {ev.entities}")
    print("  event JSON:")
    print("    " + json.dumps(ev.to_dict(), default=str))


def run() -> int:
    store = EventStore()
    print("#" * 92)
    print("PHASE 4 — L0 (mail/endpoint) + L1 (boundary) detection : catching attacks 1-3")
    print("#" * 92)

    mail_ev = pipeline.run_l0_mail(store)
    _show("ATTACK #1 (phishing)  ->  L0 mail classifier", mail_ev)

    endpoint_ev = pipeline.run_l0_endpoint(store)
    _show("ATTACK #2 (malware)   ->  L0 endpoint (rules + IsolationForest)", endpoint_ev)

    l1 = pipeline.run_l1_boundary(store)
    boundary_ev = l1["flagged"][0] if l1["flagged"] else None
    _show("ATTACK #3 (boundary)  ->  L1 boundary baseline", boundary_ev)

    print("\n" + "=" * 92)
    print("FALSE-POSITIVE SPOT-CHECK (legitimate inputs must NOT alert)")
    print("=" * 92)
    fp = pipeline.false_positive_check(store)
    print(f"  benign email flagged?        {fp['benign_mail_flagged']}  "
          f"(phishing score {fp['benign_mail_score']:.3f})")
    print(f"  benign endpoint flagged?     {fp['benign_endpoint_flagged']}")
    print(f"  legit boundary FP count:     {len(l1['false_positives'])} "
          f"(baseline learned from {l1['n_baseline_events']} legitimate events)")

    all_good = (mail_ev is not None and endpoint_ev is not None and boundary_ev is not None
                and not fp["benign_mail_flagged"] and not fp["benign_endpoint_flagged"]
                and len(l1["false_positives"]) == 0)
    print("\n  VERDICT:", "PASS — attacks 1-3 each produced an event; legit traffic stayed clean."
          if all_good else "CHECK — see output above.")
    print(f"  total events in store: {len(store)}")
    return 0 if all_good else 1


def run_phase5() -> int:
    """Phase 5: L2 protocol + L3 physics catch attacks 4-7. Headline = FDIA."""
    store = EventStore()
    print("#" * 92)
    print("PHASE 5 — L2 (protocol) + L3 (physics) detection : catching attacks 4-7")
    print("#" * 92)

    # ---- L2: replay (#4) + setpoint (#5) ----
    l2 = pipeline.run_l2_protocol(store)
    print("\n" + "=" * 92)
    print("ATTACKS #4 (replay) + #5 (setpoint)  ->  L2 protocol")
    print("=" * 92)
    print(f"  baseline masters={l2['masters']}  write-rate ceiling={l2['rate_ceiling']:.0f}/s  "
          f"(learned from {l2['n_baseline_events']} legit events)")
    print(f"  false positives on legit traffic: {len(l2['false_positives'])}")
    for det in sorted(l2["by_detector"]):
        for ev in l2["by_detector"][det]:
            print(f"    · {ev.detector:26s} conf={ev.confidence:.2f} :: {ev.title}")
    replay_caught = any("replay" in d for d in l2["by_detector"])
    setpoint_caught = any(e.evidence.get("src") == "setpoint-injector"
                          for evs in l2["by_detector"].values() for e in evs)

    # ---- L3: HMI blinding (#7) ----
    l3h = pipeline.run_l3_hmi(store)
    print("\n" + "=" * 92)
    print("ATTACK #7 (HMI blinding)  ->  L3 breaker/flow consistency")
    print("=" * 92)
    print(f"  false positives on healthy view: {len(l3h['false_positives'])}")
    for ev in l3h["flagged"]:
        print(f"    · {ev.detector} conf={ev.confidence:.2f} :: {ev.title}")
        print(f"      {ev.reason}")
    hmi_caught = len(l3h["flagged"]) > 0

    # ---- L3: FDIA (#6) — THE headline contrast ----
    l3f = pipeline.run_l3_fdia(store)
    print("\n" + "=" * 92)
    print("ATTACK #6 (FDIA)  ->  L3 physics : THE PROOF POINT")
    print("=" * 92)
    print(f"  conventional chi-square test : {'FLAGGED' if l3f['naive_chi2_flagged'] else 'PASSED'} "
          f"(J={l3f['naive_J']} vs threshold {l3f['naive_threshold']})")
    print(f"      -> the FDIA {'was caught by' if l3f['naive_chi2_flagged'] else 'EVADES'} the naive test "
          "(attack succeeds against conventional detection)")
    print(f"  trusted-PMU cross-check      : {'DETECTED' if l3f['fdia_detected_by_trusted_subset'] else 'missed'} "
          f"(angle gap {l3f['trusted_angle_gap_deg']} deg at the target bus)")
    print(f"      -> the full L3 check CATCHES what chi-square cannot")
    print(f"  detection latency            : {l3f['detection_latency_cycles']} estimation cycle "
          f"({l3f['detection_wall_ms']} ms)")
    if l3f["event"]:
        print("  event JSON:")
        print("    " + json.dumps(l3f["event"].to_dict(), default=str))

    fdia_proof = (not l3f["naive_chi2_flagged"]) and l3f["fdia_detected_by_trusted_subset"]
    all_good = (replay_caught and setpoint_caught and hmi_caught and fdia_proof
                and len(l2["false_positives"]) == 0 and len(l3h["false_positives"]) == 0)
    print("\n" + "=" * 92)
    print("  VERDICT:", "PASS — attacks 4,5,7 flagged; FDIA evades chi-square yet is caught "
          "by the trusted subset." if all_good else "CHECK — see output above.")
    print(f"  total events in store: {len(store)}")
    return 0 if all_good else 1


if __name__ == "__main__":
    raise SystemExit(run())
