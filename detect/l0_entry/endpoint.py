"""L0 endpoint detector — process-ancestry rules + beacon-timing anomaly model.

Two complementary detectors over the endpoint signal from attack #2:

  * a hard *rule*: an Office application spawning a shell / LOLBIN (winword or
    excel -> cmd/powershell/rundll32) is never normal, regardless of anything
    else. This alone is high-confidence.
  * an IsolationForest over behavioural features (ancestry depth, count of
    suspicious parent/child pairs, beacon count, and beacon-timing regularity =
    stdev/mean of inter-arrival times). Trained on synthesised *benign* endpoint
    behaviour (shallow trees, no office->shell, irregular or no beaconing), it
    scores the malware signal as a strong outlier — the near-constant beacon
    interval a human would never produce is the key giveaway.

The two are fused: rule OR anomaly triggers, and both firing raises confidence.
"""
from __future__ import annotations

import numpy as np

from ..events import DetectionEvent, STAGE_EXECUTION

FEATURES = ["ancestry_depth", "num_suspicious_pairs", "beacon_count", "beacon_regularity"]

# regularity = 1 - stdev/mean of beacon intervals; ~1.0 == metronome (bot),
# near 0 == human/irregular. We compute it from the signal.
SUSPICIOUS_OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SHELL_LOLBINS = {"cmd.exe", "powershell.exe", "rundll32.exe", "wscript.exe",
                 "mshta.exe", "regsvr32.exe"}


def _regularity(intervals) -> float:
    if not intervals:
        return 0.0
    mean = sum(intervals) / len(intervals)
    if mean <= 0:
        return 0.0
    stdev = (sum((x - mean) ** 2 for x in intervals) / len(intervals)) ** 0.5
    return max(0.0, 1.0 - stdev / mean)


def signal_features(signal: dict) -> dict:
    f = signal.get("features", {})
    intervals = signal.get("beacon_intervals_s", [])
    return {
        "ancestry_depth": f.get("ancestry_depth", len(signal.get("process_events", []))),
        "num_suspicious_pairs": f.get("num_suspicious_pairs", 0),
        "beacon_count": f.get("beacon_count", len(signal.get("beacons", []))),
        "beacon_regularity": round(_regularity(intervals), 3),
    }


def office_spawned_shell(signal: dict) -> list[str]:
    """Return the list of offending parent->child edges (the hard rule)."""
    hits = []
    for e in signal.get("process_events", []):
        p, c = e.get("parent", ""), e.get("child", "")
        if p in SUSPICIOUS_OFFICE_PARENTS and c in SHELL_LOLBINS:
            hits.append(f"{p}->{c}")
    return hits


def _synthesize_benign(n: int = 300, seed: int = 11) -> np.ndarray:
    """Normal endpoints: shallow process trees, no office->shell, little/no
    regular beaconing (irregular update checks at most)."""
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(n):
        rows.append([
            rng.integers(1, 3),                       # ancestry_depth: shallow
            0,                                        # num_suspicious_pairs: none
            rng.integers(0, 3),                       # beacon_count: few/none
            round(float(rng.uniform(0.0, 0.5)), 3),   # regularity: irregular
        ])
    return np.array(rows, dtype=float)


def benign_endpoint_signal() -> dict:
    """A normal endpoint: user opens a document, no shell, no regular beacon."""
    import time
    base = time.time()
    return {
        "process_events": [
            {"ts": base, "parent": "explorer.exe", "child": "excel.exe", "suspicious_pair": False},
            {"ts": base + 1, "parent": "excel.exe", "child": "excel.exe", "suspicious_pair": False},
        ],
        "beacons": [{"ts": base + 60, "dst": "update.microsoft.com:443", "bytes": 800}],
        "beacon_intervals_s": [312.0, 47.0],   # irregular update checks, not a beacon
        "features": {"ancestry_depth": 2, "office_spawned_shell": False,
                     "num_suspicious_pairs": 0, "beacon_count": 1},
        "host": {"workstation": "eng-laptop-07", "ip": "10.0.7.66", "user": "j.rivera@grid-ops.example"},
    }


class EndpointDetector:
    def __init__(self, seed: int = 11, contamination: float = 0.02):
        from sklearn.ensemble import IsolationForest
        X = _synthesize_benign(seed=seed)
        self.iforest = IsolationForest(random_state=seed, contamination=contamination,
                                       n_estimators=150)
        self.iforest.fit(X)

    def anomaly_score(self, feats: dict) -> tuple[bool, float]:
        x = np.array([[feats[k] for k in FEATURES]], dtype=float)
        is_outlier = bool(self.iforest.predict(x)[0] == -1)
        # decision_function: higher = more normal; negate to a positive anomaly score
        raw = float(self.iforest.decision_function(x)[0])
        return is_outlier, round(-raw, 4)

    def detect(self, signal: dict) -> DetectionEvent | None:
        feats = signal_features(signal)
        rule_hits = office_spawned_shell(signal)
        is_outlier, ascore = self.anomaly_score(feats)
        host = signal.get("host", {})

        if not rule_hits and not is_outlier:
            return None

        # fuse: rule is high-confidence on its own; anomaly corroborates/raises it
        reasons = []
        conf = 0.0
        if rule_hits:
            reasons.append(f"process-ancestry rule fired: Office app spawned a shell/LOLBIN "
                           f"({', '.join(rule_hits)})")
            conf = max(conf, 0.85)
        if is_outlier:
            reasons.append(f"IsolationForest flagged the endpoint as an outlier "
                           f"(anomaly score {ascore:.3f}); beacon regularity "
                           f"{feats['beacon_regularity']:.2f} (~1.0 = machine-timed)")
            conf = max(conf, 0.6) + (0.1 if rule_hits else 0.0)
        conf = min(conf, 0.98)
        sev = "high" if rule_hits else "medium"

        return DetectionEvent(
            detector="L0.endpoint.rules+iforest",
            layer="L0",
            attack_stage=STAGE_EXECUTION,
            title=f"Malicious endpoint behaviour on {host.get('workstation', 'unknown')}",
            reason="; ".join(reasons) + ".",
            confidence=round(conf, 3),
            severity=sev,
            entities={
                "workstation": host.get("workstation"),
                "host": host.get("ip"),
                "user": host.get("user"),
            },
            evidence={
                "ancestry_rule_hits": rule_hits,
                "isolation_forest_outlier": is_outlier,
                "anomaly_score": ascore,
                **feats,
            },
            assets=[host.get("workstation")] if host.get("workstation") else [],
        )
