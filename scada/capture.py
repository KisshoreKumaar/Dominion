"""Modbus traffic capture — GRIDSENTINEL's substitute for a network tap.

Every Modbus request/response in the sandbox is recorded here as a structured
``ModbusEvent``. This is the single source of truth the L1 (boundary) and L2
(protocol) detection layers will read from in Phases 4-5, so the schema is
deliberately rich and stable.

Two capture points feed the same bus:
  * ``capture_point="client"`` — logged by the capturing Modbus client wrapper
    (scada/control_center.py and, later, the attack scripts). These carry full
    *source identity* (label, host, port) because the client knows who it is.
    This is the authoritative feed for detection.
  * ``capture_point="rtu"``   — logged server-side by the RTU's datastore
    (scada/rtu_server.py) the instant a frame is serviced. These prove the
    function codes really crossed the wire and are robust to any client that
    bypasses our wrapper.

Fields (per DoD): source, dest, function code, register/address, value(s),
timestamp — plus unit id, direction, transaction id, and ok/exception status.

Storage is an in-memory ring plus optional SQLite. Reading never blocks the
grid loop; a full ring simply drops the oldest event.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass, asdict, field
from typing import Optional

# Modbus function-code -> human name and (read/write, table) classification.
FUNCTION_CODES = {
    1: ("read_coils", "read", "coil"),
    2: ("read_discrete_inputs", "read", "discrete"),
    3: ("read_holding_registers", "read", "holding"),
    4: ("read_input_registers", "read", "input"),
    5: ("write_coil", "write", "coil"),
    6: ("write_register", "write", "holding"),
    15: ("write_coils", "write", "coil"),
    16: ("write_registers", "write", "holding"),
}


def fc_name(fc: int) -> str:
    return FUNCTION_CODES.get(fc, (f"fc_{fc}", "?", "?"))[0]


def fc_is_write(fc: int) -> bool:
    return FUNCTION_CODES.get(fc, ("", "?", ""))[1] == "write"


@dataclass
class ModbusEvent:
    seq: int
    ts: float                 # epoch seconds
    ts_iso: str               # human-readable timestamp
    capture_point: str        # "client" | "rtu"
    src: str                  # e.g. "control-center" or "10.0.0.9:5511"
    src_host: str
    src_port: int
    dst: str                  # e.g. "rtu-15"
    dst_host: str
    dst_port: int
    unit_id: int
    direction: str            # "read" | "write"
    function_code: int
    fc_name: str
    address: int
    count: int
    values: list              # register values or coil bools
    transaction_id: Optional[int] = None
    ok: bool = True           # False if the response was an exception
    exception: Optional[str] = None
    # free-form decoded meaning filled in by higher layers (e.g. "open breaker line 26")
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class CaptureBus:
    """Append-mostly store of Modbus events, thread-safe, fail-open."""

    def __init__(self, maxlen: int = 20000, sqlite_path: Optional[str] = None):
        self._events: deque[ModbusEvent] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._seq = 0
        self._subscribers: list = []
        self._sqlite_path = sqlite_path
        self._conn: Optional[sqlite3.Connection] = None
        if sqlite_path:
            self._init_sqlite(sqlite_path)

    def _init_sqlite(self, path: str) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS modbus_events (
                seq INTEGER PRIMARY KEY, ts REAL, ts_iso TEXT, capture_point TEXT,
                src TEXT, src_host TEXT, src_port INTEGER, dst TEXT, dst_host TEXT,
                dst_port INTEGER, unit_id INTEGER, direction TEXT, function_code INTEGER,
                fc_name TEXT, address INTEGER, count INTEGER, values_json TEXT,
                transaction_id INTEGER, ok INTEGER, exception TEXT, note TEXT)"""
        )
        self._conn.commit()

    def record(
        self,
        *,
        capture_point: str,
        src: str,
        dst: str,
        unit_id: int,
        function_code: int,
        address: int,
        count: int = 1,
        values=None,
        src_host: str = "127.0.0.1",
        src_port: int = 0,
        dst_host: str = "127.0.0.1",
        dst_port: int = 0,
        transaction_id: Optional[int] = None,
        ok: bool = True,
        exception: Optional[str] = None,
        note: str = "",
        ts: Optional[float] = None,
    ) -> ModbusEvent:
        name, direction, _table = FUNCTION_CODES.get(function_code, (f"fc_{function_code}", "?", "?"))
        # ts override lets an attack backdate an event (e.g. an off-hours session)
        # so L1's hour-of-day baseline sees the implausible operator time.
        now = ts if ts is not None else time.time()
        with self._lock:
            self._seq += 1
            ev = ModbusEvent(
                seq=self._seq,
                ts=now,
                ts_iso=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)) + f".{int((now%1)*1000):03d}",
                capture_point=capture_point,
                src=src, src_host=src_host, src_port=src_port,
                dst=dst, dst_host=dst_host, dst_port=dst_port,
                unit_id=unit_id, direction=direction,
                function_code=function_code, fc_name=name,
                address=address, count=count,
                values=list(values) if values is not None else [],
                transaction_id=transaction_id, ok=ok, exception=exception, note=note,
            )
            self._events.append(ev)
            if self._conn is not None:
                try:
                    self._conn.execute(
                        "INSERT OR REPLACE INTO modbus_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (ev.seq, ev.ts, ev.ts_iso, ev.capture_point, ev.src, ev.src_host,
                         ev.src_port, ev.dst, ev.dst_host, ev.dst_port, ev.unit_id,
                         ev.direction, ev.function_code, ev.fc_name, ev.address, ev.count,
                         json.dumps(ev.values), ev.transaction_id, int(ev.ok), ev.exception, ev.note),
                    )
                    self._conn.commit()
                except Exception:
                    pass  # persistence must never break capture
        # notify subscribers (e.g. live detection) outside the lock, fail-open
        for cb in list(self._subscribers):
            try:
                cb(ev)
            except Exception:
                pass
        return ev

    def subscribe(self, callback) -> None:
        self._subscribers.append(callback)

    def events(self, capture_point: Optional[str] = None, limit: Optional[int] = None) -> list[ModbusEvent]:
        with self._lock:
            evs = list(self._events)
        if capture_point:
            evs = [e for e in evs if e.capture_point == capture_point]
        if limit:
            evs = evs[-limit:]
        return evs

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def __len__(self) -> int:
        return len(self._events)


# Process-wide default bus so every subsystem shares one tap without plumbing.
GLOBAL_CAPTURE = CaptureBus()


def get_capture() -> CaptureBus:
    return GLOBAL_CAPTURE
