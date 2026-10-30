"""Phase 4 DoD tests: attacks 1-3 each produce a detection event; legitimate
inputs stay below threshold (informal FP check).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detect.events import EventStore, DetectionEvent
from detect.l0_entry.mail import MailClassifier, benign_email_sample
from detect.l0_entry.endpoint import EndpointDetector, benign_endpoint_signal
from detect import pipeline


# ---------------- event schema ----------------

def test_detection_event_schema_roundtrips():
    ev = DetectionEvent(detector="L0.mail.gbm", layer="L0", attack_stage="delivery",
                        title="t", reason="r", confidence=0.9, severity="high",
                        entities={"host": "10.0.7.66"})
    d = ev.to_dict()
    assert d["event_id"] and d["ts_iso"] and d["layer"] == "L0"
    assert json.loads(json.dumps(d))  # JSON-serialisable
    assert ev.severity_rank() == 3


def test_event_store_filters():
    store = EventStore()
    store.emit(DetectionEvent("d", "L0", "delivery", "t", "r", 0.9, "high"))
    store.emit(DetectionEvent("d", "L1", "boundary-traversal", "t", "r", 0.2, "low"))
    assert len(store.events(layer="L0")) == 1
    assert len(store.events(min_severity="medium")) == 1
    assert len(store.events(min_confidence=0.5)) == 1


# ---------------- L0 mail ----------------

def test_l0_mail_flags_phishing_attack():
    from attacks.phishing import phishing_sample
    clf = MailClassifier()
    ev = clf.detect(phishing_sample())
    assert ev is not None, "phishing email must be flagged"
    assert ev.confidence >= clf.threshold
    assert ev.layer == "L0" and ev.attack_stage == "delivery"
    assert "classifier scored" in ev.reason           # explainable verdict


def test_l0_mail_ignores_benign_email():
    clf = MailClassifier()
    assert clf.detect(benign_email_sample()) is None
    assert clf.score(benign_email_sample()["features"]) < clf.threshold


# ---------------- L0 endpoint ----------------

def test_l0_endpoint_flags_malware_signal():
    from attacks.malware import build_signal
    det = EndpointDetector()
    ev = det.detect(build_signal())
    assert ev is not None
    assert ev.evidence["ancestry_rule_hits"], "office->shell rule should fire"
    assert ev.confidence >= 0.6


def test_l0_endpoint_ignores_benign_signal():
    det = EndpointDetector()
    assert det.detect(benign_endpoint_signal()) is None


# ---------------- L1 boundary ----------------

def test_l1_boundary_flags_novel_session_and_not_legit():
    store = EventStore()
    res = pipeline.run_l1_boundary(store)
    # the attacker session is flagged
    assert len(res["flagged"]) >= 1
    ev = res["flagged"][0]
    assert ev.entities["host"] == "10.0.7.66"
    assert ev.evidence["first_seen_source"] is True
    assert ev.layer == "L1"
    # legitimate control-center traffic produced no false positives
    assert len(res["false_positives"]) == 0
    assert res["n_baseline_events"] > 0


# ---------------- DoD: one event per attack class, no FP ----------------

def test_phase4_dod_all_three_detected_no_fp():
    store = EventStore()
    mail = pipeline.run_l0_mail(store)
    endpoint = pipeline.run_l0_endpoint(store)
    l1 = pipeline.run_l1_boundary(store)
    fp = pipeline.false_positive_check(store)

    assert mail is not None and endpoint is not None and l1["flagged"]
    assert not fp["benign_mail_flagged"]
    assert not fp["benign_endpoint_flagged"]
    assert len(l1["false_positives"]) == 0
    # three attack classes, three (or more) events in the shared store
    assert len(store) >= 3
