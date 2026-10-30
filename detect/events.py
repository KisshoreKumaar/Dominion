"""Detection event schema + shared event store.

THIS SCHEMA IS ARCHITECTURE-CRITICAL: every detector (L0-L3, Phases 4-5) writes
``DetectionEvent``s here, and the Phase 6 correlation engine builds its attack
graph out of them. So the schema carries not just "what fired" but everything
the correlator needs to stitch scattered events into one incident:

  * a stable ``layer`` / ``detector`` / ``attack_stage`` so the graph can order
    events along the kill chain,
  * an ``entities`` bag (hosts, workstations, RTUs, mailboxes, lines...) so the
    correlator can link events that touch the same asset/actor across time,
  * an explainable ``reason`` carrying the specific rule / threshold / score
    that fired (Section 1: never a bare "anomaly detected"),
  * ``confidence`` and ``severity`` for promotion/scoring.

Keep this additive: downstream code should tolerate new optional fields.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional

# kill-chain stages (used by Phase 6 to order the attack graph)
STAGE_DELIVERY = "delivery"            # phishing mail arrives
STAGE_EXECUTION = "execution"         # malware runs on endpoint
STAGE_BOUNDARY = "boundary-traversal"  # IT -> OT crossing
STAGE_COMMAND = "command"             # unauthorized SCADA command
STAGE_MANIPULATION = "manipulation"   # data/view manipulation (FDIA / HMI)
STAGE_PHYSICAL = "physical"           # physical grid impact

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class DetectionEvent:
    detector: str                     # e.g. "L0.mail.gbm"
    layer: str                        # "L0" | "L1" | "L2" | "L3"
    attack_stage: str                 # one of the STAGE_* constants
    title: str                        # short human summary
    reason: str                       # explainable: the rule/threshold/value that fired
    confidence: float                 # 0.0 - 1.0
    severity: str = "medium"          # info|low|medium|high|critical
    entities: dict = field(default_factory=dict)   # {"src_host":..,"dst_rtu":..,"workstation":..}
    evidence: dict = field(default_factory=dict)    # structured facts behind the verdict
    assets: list = field(default_factory=list)      # asset ids touched
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: float = field(default_factory=time.time)
    ts_iso: str = ""

    def __post_init__(self):
        if not self.ts_iso:
            self.ts_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.ts)) + \
                f".{int((self.ts % 1) * 1000):03d}"

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict:
        return asdict(self)

    def one_line(self) -> str:
        return (f"[{self.ts_iso}] {self.layer} {self.detector} "
                f"sev={self.severity} conf={self.confidence:.2f} :: {self.title}")


class EventStore:
    """Shared, thread-safe store of detection events (in-memory + optional SQLite).

    Detectors call ``emit``; Phase 6 reads via ``events`` / ``subscribe``.
    """

    def __init__(self, sqlite_path: Optional[str] = None, maxlen: int = 50000):
        self._events: list[DetectionEvent] = []
        self._lock = threading.Lock()
        self._subscribers: list = []
        self._maxlen = maxlen
        self._conn: Optional[sqlite3.Connection] = None
        if sqlite_path:
            self._conn = sqlite3.connect(sqlite_path, check_same_thread=False)
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS detection_events (
                    event_id TEXT PRIMARY KEY, ts REAL, ts_iso TEXT, detector TEXT,
                    layer TEXT, attack_stage TEXT, title TEXT, reason TEXT,
                    confidence REAL, severity TEXT, entities_json TEXT,
                    evidence_json TEXT, assets_json TEXT)""")
            self._conn.commit()

    def emit(self, event: DetectionEvent) -> DetectionEvent:
        with self._lock:
            self._events.append(event)
            if len(self._events) > self._maxlen:
                self._events = self._events[-self._maxlen:]
            if self._conn is not None:
                try:
                    self._conn.execute(
                        "INSERT OR REPLACE INTO detection_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (event.event_id, event.ts, event.ts_iso, event.detector, event.layer,
                         event.attack_stage, event.title, event.reason, event.confidence,
                         event.severity, json.dumps(event.entities), json.dumps(event.evidence),
                         json.dumps(event.assets)))
                    self._conn.commit()
                except Exception:
                    pass
        for cb in list(self._subscribers):
            try:
                cb(event)
            except Exception:
                pass
        return event

    def subscribe(self, callback) -> None:
        self._subscribers.append(callback)

    def events(self, layer: Optional[str] = None, min_severity: Optional[str] = None,
               min_confidence: float = 0.0) -> list[DetectionEvent]:
        with self._lock:
            evs = list(self._events)
        if layer:
            evs = [e for e in evs if e.layer == layer]
        if min_severity:
            floor = SEVERITY_ORDER.get(min_severity, 0)
            evs = [e for e in evs if e.severity_rank() >= floor]
        if min_confidence > 0:
            evs = [e for e in evs if e.confidence >= min_confidence]
        return evs

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def __len__(self) -> int:
        return len(self._events)


# process-wide default store so every detector + the correlator share one bus
GLOBAL_EVENTS = EventStore()


def get_event_store() -> EventStore:
    return GLOBAL_EVENTS
