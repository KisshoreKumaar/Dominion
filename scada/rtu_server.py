"""RTU simulators — one Modbus/TCP server per instrumented substation.

Each RTU is a real ``pymodbus`` TCP server on its own port. Its datastore is a
``CapturingSlaveContext`` that:
  * logs every serviced read/write to the capture bus (capture_point="rtu"),
    proving real Modbus function codes cross the wire, and
  * bridges incoming writes to the shared GridEngine: a coil write opens/closes
    a breaker, a holding-register write changes a generator setpoint or trafo
    tap — so control-center commands actually move the pandapower model.

A background updater copies the latest GridSnapshot into every RTU's input
registers / discrete inputs each tick, so the control center reads live values.

Design note (Section 1 constraints): the RTUs share the GridEngine object
in-process rather than running as separate OS processes. What matters for the
demo and for detection is *real protocol frames on real sockets*, which this
delivers; separate OS processes would only add a distributed state-sync problem
with no benefit to the attack/detect story. The write path from Modbus into the
grid is the ONLY place SCADA mutates the process, exactly as Section 1 requires.
"""
from __future__ import annotations

import asyncio
import threading
from typing import Optional

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import ModbusTcpServer

from grid.engine import GridEngine
from . import rtu_map as rm
from .capture import CaptureBus, get_capture, fc_is_write

# pymodbus passes the function code to getValues/setValues as its first arg.
# Map it to which data table is being touched.
_FC_TABLE = {1: "co", 5: "co", 15: "co", 2: "di", 3: "hr", 6: "hr", 16: "hr", 4: "ir"}


class CapturingSlaveContext(ModbusSlaveContext):
    """A slave context wired to one RTU: captures traffic and bridges writes."""

    def __init__(self, spec: rm.RTUSpec, engine: GridEngine, capture: CaptureBus):
        # Size the blocks generously. NOTE: the base context adds +1 to every
        # address before indexing the block, so we always read/write through the
        # base ModbusSlaveContext methods (never self.store directly) to keep the
        # measurement refresh consistent with what clients read.
        super().__init__(
            di=ModbusSequentialDataBlock(0, [False] * 64),
            co=ModbusSequentialDataBlock(0, [False] * 64),
            ir=ModbusSequentialDataBlock(0, [0] * 64),
            hr=ModbusSequentialDataBlock(0, [0] * 64),
        )
        self.spec = spec
        self.engine = engine
        self.capture = capture
        # HMI-blinding (attack #7): when frozen, the measurement refresh is
        # skipped so the RTU keeps reporting its last (stale/nominal) values to
        # the control center while the real grid diverges underneath it.
        self.frozen = False

    def _raw_set(self, fc: int, address: int, values: list) -> None:
        """Write through the base context (applies the standard +1 offset) but
        WITHOUT our capture/bridge overrides. FC only selects the table:
        4->input, 2->discrete, 1->coil, 3->holding."""
        ModbusSlaveContext.setValues(self, fc, address, values)

    # ---- capture + bridge on every serviced request ----

    def getValues(self, fc_as_hex, address, count=1):
        values = super().getValues(fc_as_hex, address, count)
        self.capture.record(
            capture_point="rtu",
            src="wire",  # server side doesn't see peer identity; client wrapper supplies it
            dst=self.spec.rtu_id,
            dst_host=self.spec.host, dst_port=self.spec.port,
            unit_id=self.spec.unit_id,
            function_code=int(fc_as_hex),
            address=int(address), count=int(count),
            values=list(values),
        )
        return values

    def setValues(self, fc_as_hex, address, values):
        super().setValues(fc_as_hex, address, values)
        fc = int(fc_as_hex)
        note = self._bridge_write(fc, int(address), list(values))
        self.capture.record(
            capture_point="rtu",
            src="wire",
            dst=self.spec.rtu_id,
            dst_host=self.spec.host, dst_port=self.spec.port,
            unit_id=self.spec.unit_id,
            function_code=fc,
            address=int(address), count=len(values),
            values=list(values),
            note=note,
        )

    def _bridge_write(self, fc: int, address: int, values: list) -> str:
        """Apply an incoming write to the grid engine. Returns a decoded note."""
        table = _FC_TABLE.get(fc)
        notes = []
        if table == "co":
            # coil write(s) -> breaker command(s) on monitored lines
            for i, v in enumerate(values):
                slot = address + i
                if slot < len(self.spec.lines):
                    line_id = self.spec.lines[slot]
                    closed = bool(v)
                    self.engine.set_breaker(
                        "line", line_id, closed=closed,
                        reason=f"SCADA write FC{fc} {self.spec.rtu_id} coil{slot}",
                    )
                    notes.append(f"{'close' if closed else 'OPEN'} breaker line {line_id}")
        elif table == "hr":
            for i, v in enumerate(values):
                slot = address + i
                if slot == rm.HR_GEN_SETPOINT and self.spec.gen_id is not None:
                    mw = rm.dec_mw(v)
                    self.engine.set_gen_setpoint(
                        self.spec.gen_id, mw,
                        reason=f"SCADA write FC{fc} {self.spec.rtu_id} gen setpoint",
                    )
                    notes.append(f"gen {self.spec.gen_id} setpoint -> {mw:.1f} MW")
                elif slot == rm.HR_TAP_POS and self.spec.trafo_id is not None:
                    tap = rm.dec_tap(v)
                    self.engine.set_trafo_tap(
                        self.spec.trafo_id, tap,
                        reason=f"SCADA write FC{fc} {self.spec.rtu_id} tap",
                    )
                    notes.append(f"trafo {self.spec.trafo_id} tap -> {tap}")
        return "; ".join(notes)

    # ---- internal measurement refresh (NOT captured; not wire traffic) ----

    def refresh_from_snapshot(self, snap) -> None:
        """Push live grid measurements into IR/DI (and mirror breaker state to
        coils). Writes straight to the blocks, bypassing capture/bridge."""
        if self.frozen:
            return  # HMI blinding: hold stale values, ignore the live grid
        spec = self.spec
        # bus measurements
        bus = next((b for b in snap.buses if b.bus_id == spec.bus), None)
        ir = {}
        if bus is not None:
            ir[rm.IR_VM] = rm.enc_vm(bus.vm_pu)
            ir[rm.IR_VA] = rm.enc_va(bus.va_degree)
            ir[rm.IR_BUS_P] = rm.enc_mw(bus.p_mw)
        ir[rm.IR_FREQ] = rm.enc_freq(snap.frequency_hz)
        # per-line measurements + breaker status
        di_vals = [False] * len(spec.lines)
        co_vals = [False] * len(spec.lines)
        line_by_id = {l.line_id: l for l in snap.lines}
        for slot, line_id in enumerate(spec.lines):
            ln = line_by_id.get(line_id)
            if ln is None:
                continue
            ir[rm.IR_LINE_P_BASE + slot] = rm.enc_mw(ln.p_from_mw)
            ir[rm.IR_LINE_LOAD_BASE + slot] = rm.enc_load(ln.loading_percent)
            di_vals[slot] = ln.breaker_closed
            co_vals[slot] = ln.breaker_closed
        # local generator setpoint mirror (holding register, FC 3 table)
        if spec.gen_id is not None:
            gen = next((g for g in snap.gens if g.gen_id == spec.gen_id), None)
            if gen is not None:
                self._raw_set(3, rm.HR_GEN_SETPOINT, [rm.enc_mw(gen.p_mw)])
        # input registers (FC 4 table)
        for addr, val in ir.items():
            self._raw_set(4, addr, [val])
        # discrete inputs (FC 2 table) + coil mirror (FC 1 table)
        if di_vals:
            self._raw_set(2, rm.DI_BREAKER_BASE, di_vals)
            self._raw_set(1, rm.CO_BREAKER_BASE, co_vals)


class RTUServer:
    """Wraps one CapturingSlaveContext in a running Modbus TCP server."""

    def __init__(self, spec: rm.RTUSpec, engine: GridEngine, capture: CaptureBus):
        self.spec = spec
        self.slave = CapturingSlaveContext(spec, engine, capture)
        self.context = ModbusServerContext(slaves={spec.unit_id: self.slave}, single=False)
        self._server: Optional[ModbusTcpServer] = None

    async def serve(self) -> None:
        self._server = ModbusTcpServer(
            self.context,
            address=(self.spec.host, self.spec.port),
        )
        await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server:
            await self._server.shutdown()


class RTUFarm:
    """Runs all RTU servers + the measurement updater on one asyncio loop in a
    background thread, so callers can drive it from ordinary sync code."""

    def __init__(self, engine: GridEngine, capture: Optional[CaptureBus] = None):
        self.engine = engine
        self.capture = capture if capture is not None else get_capture()
        self.specs = rm.build_rtu_specs(engine.net)
        self.servers = [RTUServer(s, engine, self.capture) for s in self.specs]
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()

    def _refresh_all(self, snap) -> None:
        for srv in self.servers:
            try:
                srv.slave.refresh_from_snapshot(snap)
            except Exception:
                pass  # fail open — never break the grid subscriber chain

    async def _main(self) -> None:
        # seed registers with the current snapshot before accepting clients
        self._refresh_all(self.engine.snapshot)
        # keep RTU registers live: subscribe to engine snapshots
        self.engine.subscribe(lambda s: self._loop.call_soon_threadsafe(self._refresh_all, s)
                              if self._loop else None)
        tasks = [asyncio.create_task(srv.serve()) for srv in self.servers]
        # give servers a moment to bind, then signal ready
        await asyncio.sleep(0.3)
        self._ready.set()
        await asyncio.gather(*tasks)

    def start(self) -> None:
        def run():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            try:
                self._loop.run_until_complete(self._main())
            except asyncio.CancelledError:
                pass

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=10)

    def stop(self) -> None:
        if self._loop:
            for srv in self.servers:
                asyncio.run_coroutine_threadsafe(srv.stop(), self._loop)

    def set_frozen(self, rtu_id: str, frozen: bool) -> bool:
        """Freeze/unfreeze one RTU's measurement reporting (drives attack #7)."""
        for srv in self.servers:
            if srv.spec.rtu_id == rtu_id:
                srv.slave.frozen = frozen
                return True
        return False

    def endpoints(self) -> list[dict]:
        return [
            {"rtu_id": s.rtu_id, "bus": s.bus, "unit_id": s.unit_id,
             "host": s.host, "port": s.port, "lines": s.lines,
             "gen_id": s.gen_id, "trafo_id": s.trafo_id}
            for s in self.specs
        ]
