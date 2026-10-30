"""Serializable snapshot types for the grid simulation.

These are the single source of truth for what the grid publishes each tick.
The API/WebSocket layer (Phase 2+) and the frontend (Phase 7) render these
dicts directly, and the detection layers (Phase 5) read process measurements
from them, so the schema is deliberately explicit and flat.

Nothing here touches pandapower — a snapshot is a plain, already-computed
picture of the grid at one instant, safe to hand across a socket.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class BusState:
    bus_id: int
    name: str
    vn_kv: float          # nominal voltage (kV)
    vm_pu: float          # voltage magnitude (per-unit) from power flow
    va_degree: float      # voltage angle (deg)
    p_mw: float           # net active power injection at bus (MW)
    q_mvar: float         # net reactive power injection at bus (Mvar)
    in_service: bool = True


@dataclass
class LineState:
    line_id: int
    name: str
    from_bus: int
    to_bus: int
    p_from_mw: float          # active power leaving the from-bus (MW)
    q_from_mvar: float
    i_ka: float               # current magnitude (kA)
    loading_percent: float    # |I| / rating -> the overload signal
    breaker_closed: bool      # True = in service, False = tripped/open
    rating_ka: float


@dataclass
class TrafoState:
    trafo_id: int
    name: str
    hv_bus: int
    lv_bus: int
    p_hv_mw: float
    loading_percent: float
    breaker_closed: bool
    tap_pos: Optional[int] = None


@dataclass
class GenState:
    gen_id: int
    name: str
    bus: int
    p_mw: float
    q_mvar: float
    vm_pu: float
    in_service: bool
    is_slack: bool = False


@dataclass
class LoadState:
    load_id: int
    name: str
    bus: int
    p_mw: float
    q_mvar: float
    in_service: bool = True


@dataclass
class GridSnapshot:
    """A complete, renderable picture of the grid at one simulation tick."""
    tick: int
    sim_time_s: float
    converged: bool
    frequency_hz: float
    total_gen_mw: float
    total_load_mw: float
    losses_mw: float
    # spare capacity metric: how much headroom before the most-loaded element trips
    reserve_margin_mw: float
    max_line_loading_percent: float
    buses: list[BusState] = field(default_factory=list)
    lines: list[LineState] = field(default_factory=list)
    trafos: list[TrafoState] = field(default_factory=list)
    gens: list[GenState] = field(default_factory=list)
    loads: list[LoadState] = field(default_factory=list)
    # events that happened on THIS tick (e.g. "line 12 tripped on overload")
    events: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def tripped_lines(self) -> list[int]:
        return [ln.line_id for ln in self.lines if not ln.breaker_closed]

    def summary_line(self) -> str:
        """One-line console string for --grid-only mode."""
        trips = self.tripped_lines()
        trip_str = f" tripped_lines={trips}" if trips else ""
        ev = f" | {'; '.join(self.events)}" if self.events else ""
        return (
            f"[t={self.tick:04d} {self.sim_time_s:6.1f}s] "
            f"conv={'Y' if self.converged else 'N'} "
            f"f={self.frequency_hz:6.3f}Hz "
            f"gen={self.total_gen_mw:7.1f} load={self.total_load_mw:7.1f} "
            f"loss={self.losses_mw:5.1f} margin={self.reserve_margin_mw:6.1f}MW "
            f"maxload={self.max_line_loading_percent:5.1f}%{trip_str}{ev}"
        )
