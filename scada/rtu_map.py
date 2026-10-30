"""RTU / substation definitions and the Modbus register map.

We instrument a subset of the 39 buses as RTUs (remote terminal units). Each
RTU is a Modbus/TCP server representing one substation; it exposes the local
measurements and the local breaker/setpoint controls for the grid elements at
that bus.

Register map (identical layout on every RTU; unused slots read 0):

  Input Registers (FC 4, read-only analog measurements, refreshed each tick):
    IR[0]  bus voltage magnitude  vm_pu * 1000            (1050 = 1.050 pu)
    IR[1]  bus voltage angle      (va_degree + 180) * 100 (offset, unsigned)
    IR[2]  system frequency       Hz * 1000               (60000 = 60.000 Hz)
    IR[3]  bus net active power   (p_mw + OFFSET_MW) ...   (offset-encoded MW)
    IR[10 + k]  monitored line k active flow  offset-encoded MW
    IR[20 + k]  monitored line k loading      percent * 10

  Discrete Inputs (FC 2, read-only status):
    DI[k]  monitored line k breaker: 1 = closed, 0 = open

  Coils (FC 1 read / FC 5,15 write, breaker command channel):
    CO[k]  command breaker on monitored line k: 1 = close, 0 = open

  Holding Registers (FC 3 read / FC 6,16 write, setpoints):
    HR[0]  local generator active-power setpoint  offset-encoded MW (if a gen)
    HR[1]  local transformer tap position         (tap + TAP_OFFSET) (if a trafo)
    HR[2]  operator heartbeat / write-enable       (free scratch register)

Encoding: analog values are scaled and offset so they fit unsigned 16-bit
registers. Decode helpers invert this. Keeping every RTU's layout identical
makes the control-center poller and the L2 allowlists simple.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ---- register addresses ----
IR_VM = 0
IR_VA = 1
IR_FREQ = 2
IR_BUS_P = 3
IR_LINE_P_BASE = 10     # + line slot
IR_LINE_LOAD_BASE = 20  # + line slot

CO_BREAKER_BASE = 0     # coil per line slot
DI_BREAKER_BASE = 0     # discrete input per line slot

HR_GEN_SETPOINT = 0
HR_TAP_POS = 1
HR_HEARTBEAT = 2

# ---- encoding constants ----
OFFSET_MW = 2000        # MW values live in [-2000, +63535] before offset
TAP_OFFSET = 100        # tap positions in [-100, +65435]
VM_SCALE = 1000
VA_OFFSET = 180
VA_SCALE = 100
FREQ_SCALE = 1000
LOAD_SCALE = 10

MAX_LINES_PER_RTU = 6   # register slots reserved for monitored lines

# Base TCP port; RTU i listens on RTU_PORT_BASE + i.
RTU_PORT_BASE = 5020
RTU_HOST = "127.0.0.1"

# Buses instrumented as RTUs. Chosen to cover the cascade corridor
# (lines 23/26/27/28 around buses 15,20,21,22,23) plus a generator bus (32).
RTU_BUSES = [2, 15, 16, 20, 21, 22, 23, 32]


def clamp_u16(v: int) -> int:
    return max(0, min(65535, int(v)))


def enc_mw(mw: float) -> int:
    return clamp_u16(round(mw) + OFFSET_MW)


def dec_mw(reg: int) -> float:
    return float(reg) - OFFSET_MW


def enc_vm(vm_pu: float) -> int:
    return clamp_u16(round(vm_pu * VM_SCALE))


def dec_vm(reg: int) -> float:
    return reg / VM_SCALE


def enc_va(va_deg: float) -> int:
    return clamp_u16(round((va_deg + VA_OFFSET) * VA_SCALE))


def dec_va(reg: int) -> float:
    return reg / VA_SCALE - VA_OFFSET


def enc_freq(hz: float) -> int:
    return clamp_u16(round(hz * FREQ_SCALE))


def dec_freq(reg: int) -> float:
    return reg / FREQ_SCALE


def enc_load(pct: float) -> int:
    return clamp_u16(round(pct * LOAD_SCALE))


def dec_load(reg: int) -> float:
    return reg / LOAD_SCALE


def enc_tap(tap: int) -> int:
    return clamp_u16(tap + TAP_OFFSET)


def dec_tap(reg: int) -> int:
    return reg - TAP_OFFSET


@dataclass
class RTUSpec:
    rtu_id: str            # e.g. "rtu-15"
    bus: int               # pandapower bus index
    unit_id: int           # Modbus unit/slave id (1-based)
    port: int              # TCP port
    lines: list[int] = field(default_factory=list)   # monitored line indices (order = slot)
    gen_id: int | None = None      # local generator index, if any
    trafo_id: int | None = None    # local transformer index, if any

    @property
    def host(self) -> str:
        return RTU_HOST

    def line_slot(self, line_id: int) -> int | None:
        return self.lines.index(line_id) if line_id in self.lines else None


def build_rtu_specs(net) -> list[RTUSpec]:
    """Construct the RTU list from the live network topology."""
    specs: list[RTUSpec] = []
    gen_by_bus = {int(net.gen.at[i, "bus"]): int(i) for i in net.gen.index}
    trafo_by_hv = {int(net.trafo.at[i, "hv_bus"]): int(i) for i in net.trafo.index}
    trafo_by_lv = {int(net.trafo.at[i, "lv_bus"]): int(i) for i in net.trafo.index}

    for idx, bus in enumerate(RTU_BUSES):
        # lines incident to this bus (either end), capped at MAX_LINES_PER_RTU
        lines = [
            int(i) for i in net.line.index
            if int(net.line.at[i, "from_bus"]) == bus or int(net.line.at[i, "to_bus"]) == bus
        ][:MAX_LINES_PER_RTU]
        specs.append(
            RTUSpec(
                rtu_id=f"rtu-{bus:02d}",
                bus=bus,
                unit_id=idx + 1,
                port=RTU_PORT_BASE + idx,
                lines=lines,
                gen_id=gen_by_bus.get(bus),
                trafo_id=trafo_by_hv.get(bus, trafo_by_lv.get(bus)),
            )
        )
    return specs
