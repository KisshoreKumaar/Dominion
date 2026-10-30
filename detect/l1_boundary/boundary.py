"""L1 boundary detector — learned baseline over the Modbus capture bus.

Learns what *normal* IT/OT-boundary traffic looks like from Phase 2's legitimate
control-center capture: the set of (source-identity -> RTU) pairs, the set of
source hosts, and the hours of day during which the boundary is normally active.
Then, over new capture events, it flags:

  * first-seen sources / (source -> RTU) pairs — a host that has never spoken
    Modbus to that RTU before (this is what catches attack #3), and
  * off-hours sessions — Modbus activity outside the learned operating window
    (corroborating signal; also uses a fixed business-hours window so it is
    deterministic regardless of when the demo runs).

Everything here is contextual: the frames themselves are perfectly valid Modbus,
so only a learned who-talks-to-whom-and-when baseline can see the anomaly.
"""
from __future__ import annotations

from ..events import DetectionEvent, STAGE_BOUNDARY

# fixed business-hours window used as a deterministic off-hours check in addition
# to whatever hours are observed in the baseline.
BUSINESS_HOURS = set(range(6, 22))   # 06:00 - 21:59 local


class BoundaryBaseline:
    def __init__(self):
        self.known_sources: set[str] = set()          # src labels
        self.known_hosts: set[str] = set()            # src hosts (IPs)
        self.known_pairs: set[tuple[str, str]] = set()  # (src_label, dst_rtu)
        self.known_hours: set[int] = set()
        self.n_learned = 0

    def learn(self, events) -> "BoundaryBaseline":
        import time
        for e in events:
            self.known_sources.add(e.src)
            self.known_hosts.add(e.src_host)
            self.known_pairs.add((e.src, e.dst))
            self.known_hours.add(time.localtime(e.ts).tm_hour)
            self.n_learned += 1
        return self


class BoundaryDetector:
    def __init__(self, baseline: BoundaryBaseline):
        self.baseline = baseline

    def detect(self, events, emit_to=None) -> list[DetectionEvent]:
        """Scan capture events, emit one DetectionEvent per anomalous *session*
        (deduplicated by (src, dst)). Only client-side events carry a real source
        identity, so we score those."""
        import time

        seen: set[tuple[str, str]] = set()
        out: list[DetectionEvent] = []
        for e in events:
            if e.capture_point != "client":
                continue
            key = (e.src, e.dst)
            if key in seen:
                continue

            first_seen_source = e.src not in self.baseline.known_sources
            first_seen_host = e.src_host not in self.baseline.known_hosts
            first_seen_pair = key not in self.baseline.known_pairs
            hour = time.localtime(e.ts).tm_hour
            off_hours = hour not in self.baseline.known_hours and hour not in BUSINESS_HOURS

            if not (first_seen_source or first_seen_pair or off_hours):
                continue
            seen.add(key)

            reasons = []
            conf = 0.0
            if first_seen_source or first_seen_host:
                reasons.append(f"first-seen source '{e.src}' ({e.src_host}) — never in the "
                               f"boundary baseline of {len(self.baseline.known_sources)} known masters")
                conf = max(conf, 0.85)
            if first_seen_pair:
                reasons.append(f"first-seen (source -> RTU) pair {e.src} -> {e.dst}")
                conf = max(conf, 0.8)
            if off_hours:
                reasons.append(f"off-hours session at {hour:02d}:xx (outside business hours "
                               f"{min(BUSINESS_HOURS):02d}:00-{max(BUSINESS_HOURS):02d}:59)")
                conf = min(conf + 0.1, 0.97) if conf else 0.55

            ev = DetectionEvent(
                detector="L1.boundary.baseline",
                layer="L1",
                attack_stage=STAGE_BOUNDARY,
                title=f"Unauthorized boundary session {e.src} -> {e.dst}",
                reason="; ".join(reasons) + ".",
                confidence=round(min(conf, 0.97), 3),
                severity="high" if (first_seen_source or first_seen_pair) else "medium",
                entities={"src_label": e.src, "host": e.src_host, "dst_rtu": e.dst},
                evidence={
                    "src_label": e.src, "src_host": e.src_host, "dst_rtu": e.dst,
                    "session_hour": hour,
                    "first_seen_source": first_seen_source,
                    "first_seen_pair": first_seen_pair,
                    "off_hours": off_hours,
                    "function_code": e.function_code,
                },
                assets=[e.dst],
                ts=e.ts,
            )
            out.append(ev)
            if emit_to is not None:
                emit_to.emit(ev)
        return out
