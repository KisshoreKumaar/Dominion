"""GridEngine — the continuously running grid simulation.

Responsibilities:
  * run AC power flow once per tick,
  * apply overload protection (emergent cascades),
  * expose the resulting state as a GridSnapshot (grid/state.py),
  * offer breaker open/close hooks that later phases (SCADA writes, attacks,
    containment) drive.

Fail-open contract (Section 1): if a solve diverges or anything inside a tick
raises, the engine holds the last good snapshot and keeps ticking. The grid
loop must survive a broken tick — it is the thing every other subsystem
attaches to, and it must never be taken down by them.

The frequency value is a DEMO-GRADE PROXY, not a dynamic-swing simulation:
pandapower steady-state power flow always balances via the slack bus, so it
has no native frequency. We derive one from how far the slack injection has
moved from its nominal baseline: losing generation forces the slack to pick up
the deficit -> frequency dips; losing load does the reverse. This gives the
demo a believable frequency needle that moves in the physically correct
direction on disturbances. It is clearly labelled as a proxy everywhere.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from . import model
from .protection import OverloadProtection
from .state import (
    BusState,
    GenState,
    GridSnapshot,
    LineState,
    LoadState,
    TrafoState,
)

# Frequency proxy droop: Hz of deviation per MW of slack-injection change.
# Tuned so a ~600 MW generation loss (one large unit) yields roughly -0.5 Hz.
FREQ_DROOP_HZ_PER_MW = 0.5 / 600.0


class GridEngine:
    def __init__(
        self,
        tick_hz: float = 1.0,
        pickup_ticks: int = 3,
        threshold_percent: float = 100.0,
    ):
        self.net = model.load_case39()
        self.protection = OverloadProtection(
            pickup_ticks=pickup_ticks, threshold_percent=threshold_percent
        )
        self.tick_interval_s = 1.0 / tick_hz if tick_hz > 0 else 0.0
        self.tick = 0
        self.sim_time_s = 0.0
        self._slack_p_nominal = float(self.net["_gs_slack_p_nominal_mw"])
        # nominal setpoints, so we can restore a clean base state after an attack
        self._gen_p_nominal = {int(i): float(self.net.gen.at[i, "p_mw"]) for i in self.net.gen.index}
        self._last_snapshot: Optional[GridSnapshot] = self._build_snapshot(
            converged=True, events=["init: steady-state solved"]
        )
        self._running = False
        self._thread: Optional[threading.Thread] = None
        # queued control operations applied at the start of the next tick.
        # Tagged tuples: ("breaker", kind, idx, closed, reason),
        # ("gen_sp", gen_id, p_mw, reason), ("tap", trafo_id, tap_pos, reason).
        self._pending_ops: list[tuple] = []
        self._lock = threading.Lock()
        # subscribers get every new snapshot (used by the API layer later)
        self._subscribers: list[Callable[[GridSnapshot], None]] = []

    # ---- public control surface (used by SCADA / attacks / containment) ----

    def set_breaker(self, kind: str, idx: int, closed: bool, reason: str = "manual") -> None:
        """Queue a breaker open/close. Applied at the top of the next tick so
        the simulation stays single-writer and deterministic."""
        with self._lock:
            self._pending_ops.append(("breaker", kind, idx, closed, reason))

    def trip_line(self, line_id: int, reason: str = "manual trip") -> None:
        self.set_breaker("line", line_id, closed=False, reason=reason)

    def close_line(self, line_id: int, reason: str = "manual close") -> None:
        self.set_breaker("line", line_id, closed=True, reason=reason)

    def set_gen_setpoint(self, gen_id: int, p_mw: float, reason: str = "manual") -> None:
        """Queue a generator active-power setpoint change (used by legitimate
        operator commands and by the setpoint-manipulation attack in Phase 3)."""
        with self._lock:
            self._pending_ops.append(("gen_sp", gen_id, float(p_mw), reason))

    def set_trafo_tap(self, trafo_id: int, tap_pos: int, reason: str = "manual") -> None:
        """Queue a transformer tap-position change."""
        with self._lock:
            self._pending_ops.append(("tap", trafo_id, int(tap_pos), reason))

    def subscribe(self, callback: Callable[[GridSnapshot], None]) -> None:
        self._subscribers.append(callback)

    def restore_base(self, reason: str = "restore base state") -> None:
        """Reset to a clean base operating point: all breakers closed, generator
        setpoints back to nominal, protection counters cleared, and re-solved.
        Used to recover the grid after an attack/cascade (demos, test isolation).
        Applied immediately (not queued) since it is an out-of-band reset."""
        with self._lock:
            self._pending_ops.clear()
        for i in self.net.line.index:
            self.net.line.at[i, "in_service"] = True
        for i in self.net.trafo.index:
            self.net.trafo.at[i, "in_service"] = True
        for gid, p in self._gen_p_nominal.items():
            if gid in self.net.gen.index:
                self.net.gen.at[gid, "p_mw"] = p
        self.protection.reset()
        converged = model.run_power_flow(self.net)
        snap = self._build_snapshot(converged=converged, events=[f"GRID RESET ({reason})"])
        self._last_snapshot = snap
        self._publish(snap)

    @property
    def snapshot(self) -> GridSnapshot:
        return self._last_snapshot

    # ------------------------------- tick -----------------------------------

    def step(self) -> GridSnapshot:
        """Advance the simulation by exactly one tick and return the snapshot.

        Wrapped so any internal failure fails open: on error we keep the last
        good snapshot, mark it non-converged, and carry on.
        """
        self.tick += 1
        self.sim_time_s += self.tick_interval_s if self.tick_interval_s else 1.0
        try:
            events = self._apply_pending_ops()
            converged = model.run_power_flow(self.net)
            if not converged:
                # Fail open: hold last good electrical state, note the event.
                snap = self._clone_last_as_nonconverged(events + ["power flow did not converge; holding last good state"])
                self._last_snapshot = snap
                self._publish(snap)
                return snap

            trip_events = self._apply_protection()
            events.extend(trip_events)
            snap = self._build_snapshot(converged=True, events=events)
            self._last_snapshot = snap
            self._publish(snap)
            return snap
        except Exception as exc:  # fail open — never take down the loop
            snap = self._clone_last_as_nonconverged([f"tick error (contained): {exc!r}"])
            self._last_snapshot = snap
            self._publish(snap)
            return snap

    def _apply_pending_ops(self) -> list[str]:
        events: list[str] = []
        with self._lock:
            ops = self._pending_ops
            self._pending_ops = []
        for op in ops:
            op_type = op[0]
            if op_type == "breaker":
                _, kind, idx, closed, reason = op
                table = self.net.line if kind == "line" else self.net.trafo
                if idx not in table.index:
                    continue
                was = bool(table.at[idx, "in_service"])
                if was == closed:
                    continue  # no change
                table.at[idx, "in_service"] = closed
                if closed:
                    self.protection.clear_element(kind, idx)
                    events.append(f"{kind} {idx} breaker CLOSED ({reason})")
                else:
                    self.protection.note_external_trip(kind, idx)
                    events.append(f"{kind} {idx} breaker OPENED ({reason})")
            elif op_type == "gen_sp":
                _, gen_id, p_mw, reason = op
                if gen_id in self.net.gen.index:
                    old = float(self.net.gen.at[gen_id, "p_mw"])
                    self.net.gen.at[gen_id, "p_mw"] = p_mw
                    events.append(f"gen {gen_id} setpoint {old:.1f}->{p_mw:.1f} MW ({reason})")
            elif op_type == "tap":
                _, trafo_id, tap_pos, reason = op
                if trafo_id in self.net.trafo.index and "tap_pos" in self.net.trafo.columns:
                    old = self.net.trafo.at[trafo_id, "tap_pos"]
                    self.net.trafo.at[trafo_id, "tap_pos"] = tap_pos
                    events.append(f"trafo {trafo_id} tap {old}->{tap_pos} ({reason})")
        return events

    def _apply_protection(self) -> list[str]:
        loadings: dict[tuple[str, int], float] = {}
        for idx in self.net.line.index:
            if bool(self.net.line.at[idx, "in_service"]):
                val = self.net.res_line.at[idx, "loading_percent"]
                if val == val:  # not NaN
                    loadings[("line", idx)] = float(val)
        for idx in self.net.trafo.index:
            if bool(self.net.trafo.at[idx, "in_service"]):
                val = self.net.res_trafo.at[idx, "loading_percent"]
                if val == val:
                    loadings[("trafo", idx)] = float(val)

        trips = self.protection.evaluate(loadings)
        events: list[str] = []
        for kind, idx, loading, ticks_over in trips:
            table = self.net.line if kind == "line" else self.net.trafo
            table.at[idx, "in_service"] = False
            events.append(
                f"PROTECTION TRIP: {kind} {idx} opened after {ticks_over} ticks "
                f"over rating (loading {loading:.1f}%)"
            )
        return events

    # ---------------------------- snapshotting ------------------------------

    def _frequency_hz(self) -> float:
        try:
            slack_now = float(self.net.res_ext_grid.p_mw.sum())
        except Exception:
            return model.NOMINAL_FREQUENCY_HZ
        deviation = slack_now - self._slack_p_nominal
        return model.NOMINAL_FREQUENCY_HZ - FREQ_DROOP_HZ_PER_MW * deviation

    def _build_snapshot(self, converged: bool, events: list[str]) -> GridSnapshot:
        net = self.net
        buses = [
            BusState(
                bus_id=int(i),
                name=str(net.bus.at[i, "name"]) if "name" in net.bus.columns else f"bus_{i}",
                vn_kv=float(net.bus.at[i, "vn_kv"]),
                vm_pu=float(net.res_bus.at[i, "vm_pu"]),
                va_degree=float(net.res_bus.at[i, "va_degree"]),
                p_mw=float(net.res_bus.at[i, "p_mw"]),
                q_mvar=float(net.res_bus.at[i, "q_mvar"]),
                in_service=bool(net.bus.at[i, "in_service"]),
            )
            for i in net.bus.index
        ]

        lines = []
        max_loading = 0.0
        worst_headroom_mw = float("inf")
        for i in net.line.index:
            closed = bool(net.line.at[i, "in_service"])
            loading = float(net.res_line.at[i, "loading_percent"]) if closed else 0.0
            if loading == loading and closed:
                max_loading = max(max_loading, loading)
            p_from = float(net.res_line.at[i, "p_from_mw"]) if closed else 0.0
            rating = float(net.line.at[i, "max_i_ka"])
            # crude headroom proxy in MW: remaining % of rating * current flow
            if closed and loading > 1e-6:
                headroom = abs(p_from) * (100.0 - loading) / loading
                worst_headroom_mw = min(worst_headroom_mw, headroom)
            lines.append(
                LineState(
                    line_id=int(i),
                    name=str(net.line.at[i, "name"]) if "name" in net.line.columns else f"line_{i}",
                    from_bus=int(net.line.at[i, "from_bus"]),
                    to_bus=int(net.line.at[i, "to_bus"]),
                    p_from_mw=p_from,
                    q_from_mvar=float(net.res_line.at[i, "q_from_mvar"]) if closed else 0.0,
                    i_ka=float(net.res_line.at[i, "i_ka"]) if closed else 0.0,
                    loading_percent=loading,
                    breaker_closed=closed,
                    rating_ka=rating,
                )
            )

        trafos = []
        for i in net.trafo.index:
            closed = bool(net.trafo.at[i, "in_service"])
            loading = float(net.res_trafo.at[i, "loading_percent"]) if closed else 0.0
            if loading == loading and closed:
                max_loading = max(max_loading, loading)
            trafos.append(
                TrafoState(
                    trafo_id=int(i),
                    name=str(net.trafo.at[i, "name"]) if "name" in net.trafo.columns else f"trafo_{i}",
                    hv_bus=int(net.trafo.at[i, "hv_bus"]),
                    lv_bus=int(net.trafo.at[i, "lv_bus"]),
                    p_hv_mw=float(net.res_trafo.at[i, "p_hv_mw"]) if closed else 0.0,
                    loading_percent=loading,
                    breaker_closed=closed,
                    tap_pos=int(net.trafo.at[i, "tap_pos"]) if "tap_pos" in net.trafo.columns and net.trafo.at[i, "tap_pos"] == net.trafo.at[i, "tap_pos"] else None,
                )
            )

        gens = []
        slack_bus = int(net["_gs_slack_bus"])
        for i in net.gen.index:
            gens.append(
                GenState(
                    gen_id=int(i),
                    name=str(net.gen.at[i, "name"]) if "name" in net.gen.columns else f"gen_{i}",
                    bus=int(net.gen.at[i, "bus"]),
                    p_mw=float(net.res_gen.at[i, "p_mw"]),
                    q_mvar=float(net.res_gen.at[i, "q_mvar"]),
                    vm_pu=float(net.res_gen.at[i, "vm_pu"]),
                    in_service=bool(net.gen.at[i, "in_service"]),
                    is_slack=False,
                )
            )
        # represent the ext_grid (slack) as a generator too, so the UI sees it
        for i in net.ext_grid.index:
            gens.append(
                GenState(
                    gen_id=1000 + int(i),
                    name=f"slack_{i}",
                    bus=int(net.ext_grid.at[i, "bus"]),
                    p_mw=float(net.res_ext_grid.at[i, "p_mw"]),
                    q_mvar=float(net.res_ext_grid.at[i, "q_mvar"]),
                    vm_pu=float(net.res_bus.at[slack_bus, "vm_pu"]),
                    in_service=bool(net.ext_grid.at[i, "in_service"]),
                    is_slack=True,
                )
            )

        loads = [
            LoadState(
                load_id=int(i),
                name=str(net.load.at[i, "name"]) if "name" in net.load.columns else f"load_{i}",
                bus=int(net.load.at[i, "bus"]),
                p_mw=float(net.res_load.at[i, "p_mw"]) if len(net.res_load) else float(net.load.at[i, "p_mw"]),
                q_mvar=float(net.res_load.at[i, "q_mvar"]) if len(net.res_load) else float(net.load.at[i, "q_mvar"]),
                in_service=bool(net.load.at[i, "in_service"]),
            )
            for i in net.load.index
        ]

        total_gen = float(net.res_gen.p_mw.sum() + net.res_ext_grid.p_mw.sum())
        total_load = float(net.res_load.p_mw.sum()) if len(net.res_load) else float(net.load[net.load.in_service].p_mw.sum())
        losses = total_gen - total_load
        margin = 0.0 if worst_headroom_mw == float("inf") else worst_headroom_mw

        return GridSnapshot(
            tick=self.tick,
            sim_time_s=round(self.sim_time_s, 2),
            converged=converged,
            frequency_hz=round(self._frequency_hz(), 4),
            total_gen_mw=round(total_gen, 2),
            total_load_mw=round(total_load, 2),
            losses_mw=round(losses, 2),
            reserve_margin_mw=round(margin, 2),
            max_line_loading_percent=round(max_loading, 2),
            buses=buses,
            lines=lines,
            trafos=trafos,
            gens=gens,
            loads=loads,
            events=events,
        )

    def _clone_last_as_nonconverged(self, events: list[str]) -> GridSnapshot:
        base = self._last_snapshot
        # Shallow copy of the last good snapshot with updated bookkeeping.
        import copy

        snap = copy.deepcopy(base)
        snap.tick = self.tick
        snap.sim_time_s = round(self.sim_time_s, 2)
        snap.converged = False
        snap.events = events
        return snap

    def _publish(self, snap: GridSnapshot) -> None:
        for cb in list(self._subscribers):
            try:
                cb(snap)
            except Exception:
                # A misbehaving subscriber must never break the grid loop.
                pass

    # ------------------------------ run loop --------------------------------

    def run(self, ticks: Optional[int] = None, realtime: bool = True,
            on_tick: Optional[Callable[[GridSnapshot], None]] = None) -> None:
        """Run the loop synchronously for ``ticks`` iterations (or forever)."""
        self._running = True
        n = 0
        while self._running and (ticks is None or n < ticks):
            start = time.time()
            snap = self.step()
            if on_tick:
                on_tick(snap)
            n += 1
            if realtime and self.tick_interval_s > 0:
                elapsed = time.time() - start
                sleep = self.tick_interval_s - elapsed
                if sleep > 0:
                    time.sleep(sleep)
        self._running = False

    def start_background(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._running = True
        self._thread = threading.Thread(target=self.run, kwargs={"realtime": True}, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
