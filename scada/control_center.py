"""Control center — the SCADA master that polls RTUs and issues operator commands.

`CapturingModbusClient` wraps a real ``pymodbus`` TCP client. Every request it
sends is logged to the capture bus with capture_point="client" and full *source
identity* (label, host, ephemeral port), which the server side cannot see. This
is the authoritative feed for L1 boundary detection (host-pair / hour) and L2
protocol detection (function-code allowlists, write-rate) in later phases.

`ControlCenter` polls every RTU each cycle (FC 4 read_input_registers, FC 3
read_holding_registers, FC 2 read_discrete_inputs) and can issue legitimate
operator commands (FC 5 write_coil, FC 6 write_register, FC 15 write_coils,
FC 16 write_registers) that flow through the RTU into the pandapower model.
"""
from __future__ import annotations

import threading
import time
from typing import Optional

from pymodbus.client import ModbusTcpClient

from . import rtu_map as rm
from .capture import CaptureBus, get_capture


class CapturingModbusClient:
    """Thin capturing wrapper around one pymodbus TCP client -> one RTU."""

    def __init__(self, spec: rm.RTUSpec, src_label: str = "control-center",
                 capture: Optional[CaptureBus] = None, src_host: str = "127.0.0.1"):
        self.spec = spec
        self.src_label = src_label
        self.src_host = src_host
        self.capture = capture if capture is not None else get_capture()
        self.client = ModbusTcpClient(spec.host, port=spec.port, timeout=2)
        self._src_port = 0
        # attacks may backdate their capture events to an off-hours time
        self.ts_override: Optional[float] = None

    def connect(self) -> bool:
        ok = self.client.connect()
        try:
            self._src_port = self.client.socket.getsockname()[1]
        except Exception:
            self._src_port = 0
        return ok

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass

    def _log(self, fc: int, address: int, count: int, values, ok: bool,
             exception: Optional[str] = None, note: str = "") -> None:
        self.capture.record(
            capture_point="client",
            src=f"{self.src_label}",
            src_host=self.src_host, src_port=self._src_port,
            dst=self.spec.rtu_id, dst_host=self.spec.host, dst_port=self.spec.port,
            unit_id=self.spec.unit_id,
            function_code=fc, address=address, count=count,
            values=values, ok=ok, exception=exception, note=note,
            ts=self.ts_override,
        )

    # ---- reads (poll) ----
    def read_input_registers(self, address: int, count: int) -> list[int]:
        rr = self.client.read_input_registers(address, count=count, slave=self.spec.unit_id)
        ok = not rr.isError()
        vals = list(rr.registers) if ok else []
        self._log(4, address, count, vals, ok, None if ok else str(rr))
        return vals

    def read_holding_registers(self, address: int, count: int) -> list[int]:
        rr = self.client.read_holding_registers(address, count=count, slave=self.spec.unit_id)
        ok = not rr.isError()
        vals = list(rr.registers) if ok else []
        self._log(3, address, count, vals, ok, None if ok else str(rr))
        return vals

    def read_discrete_inputs(self, address: int, count: int) -> list[bool]:
        rr = self.client.read_discrete_inputs(address, count=count, slave=self.spec.unit_id)
        ok = not rr.isError()
        vals = list(rr.bits)[:count] if ok else []
        self._log(2, address, count, vals, ok, None if ok else str(rr))
        return vals

    # ---- writes (commands) ----
    def write_coil(self, address: int, value: bool, note: str = "") -> bool:
        rr = self.client.write_coil(address, bool(value), slave=self.spec.unit_id)
        ok = not rr.isError()
        self._log(5, address, 1, [bool(value)], ok, None if ok else str(rr), note)
        return ok

    def write_register(self, address: int, value: int, note: str = "") -> bool:
        rr = self.client.write_register(address, int(value), slave=self.spec.unit_id)
        ok = not rr.isError()
        self._log(6, address, 1, [int(value)], ok, None if ok else str(rr), note)
        return ok

    def write_coils(self, address: int, values: list, note: str = "") -> bool:
        rr = self.client.write_coils(address, [bool(v) for v in values], slave=self.spec.unit_id)
        ok = not rr.isError()
        self._log(15, address, len(values), [bool(v) for v in values], ok, None if ok else str(rr), note)
        return ok

    def write_registers(self, address: int, values: list, note: str = "") -> bool:
        rr = self.client.write_registers(address, [int(v) for v in values], slave=self.spec.unit_id)
        ok = not rr.isError()
        self._log(16, address, len(values), [int(v) for v in values], ok, None if ok else str(rr), note)
        return ok


class ControlCenter:
    """SCADA master over all RTUs."""

    def __init__(self, specs: list[rm.RTUSpec], capture: Optional[CaptureBus] = None,
                 src_label: str = "control-center"):
        self.specs = specs
        self.capture = capture if capture is not None else get_capture()
        self.clients: dict[str, CapturingModbusClient] = {
            s.rtu_id: CapturingModbusClient(s, src_label=src_label, capture=self.capture)
            for s in specs
        }
        self._by_id = {s.rtu_id: s for s in specs}
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def connect(self) -> None:
        for c in self.clients.values():
            c.connect()

    def close(self) -> None:
        for c in self.clients.values():
            c.close()

    # ---- polling ----
    def poll_rtu(self, rtu_id: str) -> dict:
        spec = self._by_id[rtu_id]
        c = self.clients[rtu_id]
        n_lines = len(spec.lines)
        ir = c.read_input_registers(0, 26)                 # FC 4: analog block
        hr = c.read_holding_registers(0, 3)                # FC 3: setpoints
        di = c.read_discrete_inputs(0, max(1, n_lines))    # FC 2: breaker status
        decoded = {
            "rtu_id": rtu_id, "bus": spec.bus,
            "vm_pu": rm.dec_vm(ir[rm.IR_VM]) if len(ir) > rm.IR_VM else None,
            "va_deg": rm.dec_va(ir[rm.IR_VA]) if len(ir) > rm.IR_VA else None,
            "freq_hz": rm.dec_freq(ir[rm.IR_FREQ]) if len(ir) > rm.IR_FREQ else None,
            "bus_p_mw": rm.dec_mw(ir[rm.IR_BUS_P]) if len(ir) > rm.IR_BUS_P else None,
            "lines": [],
            "gen_setpoint_mw": rm.dec_mw(hr[rm.HR_GEN_SETPOINT]) if hr else None,
            "breakers_closed": [bool(x) for x in di[:n_lines]],
        }
        for slot, line_id in enumerate(spec.lines):
            decoded["lines"].append({
                "line_id": line_id,
                "p_mw": rm.dec_mw(ir[rm.IR_LINE_P_BASE + slot]) if len(ir) > rm.IR_LINE_P_BASE + slot else None,
                "loading_pct": rm.dec_load(ir[rm.IR_LINE_LOAD_BASE + slot]) if len(ir) > rm.IR_LINE_LOAD_BASE + slot else None,
                "breaker_closed": bool(di[slot]) if slot < len(di) else None,
            })
        return decoded

    def poll_all(self) -> dict[str, dict]:
        return {s.rtu_id: self.poll_rtu(s.rtu_id) for s in self.specs}

    # ---- legitimate operator commands ----
    def operate_breaker(self, rtu_id: str, line_id: int, close: bool) -> bool:
        spec = self._by_id[rtu_id]
        slot = spec.line_slot(line_id)
        if slot is None:
            raise ValueError(f"{rtu_id} does not monitor line {line_id}")
        action = "close" if close else "open"
        return self.clients[rtu_id].write_coil(
            rm.CO_BREAKER_BASE + slot, close,
            note=f"operator {action} breaker line {line_id}")

    def set_generator_setpoint(self, rtu_id: str, mw: float) -> bool:
        return self.clients[rtu_id].write_register(
            rm.HR_GEN_SETPOINT, rm.enc_mw(mw),
            note=f"operator gen setpoint {mw:.1f} MW")

    def operate_breakers_multi(self, rtu_id: str, closed_states: list[bool]) -> bool:
        return self.clients[rtu_id].write_coils(
            rm.CO_BREAKER_BASE, closed_states, note="operator multi-breaker command")

    def set_setpoints_multi(self, rtu_id: str, regs: list[int]) -> bool:
        return self.clients[rtu_id].write_registers(
            rm.HR_GEN_SETPOINT, regs, note="operator multi-register command")

    # ---- background poll loop ----
    def start_polling(self, interval_s: float = 1.0) -> None:
        def loop():
            while self._running:
                try:
                    self.poll_all()
                except Exception:
                    pass  # a poll failure must not kill the loop
                time.sleep(interval_s)

        self._running = True
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop_polling(self) -> None:
        self._running = False
