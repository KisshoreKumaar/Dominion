"""Phase 2 SCADA demonstration: a legitimate operator command, end to end.

Brings up the grid + RTU farm + control center, runs a poll cycle, issues a
legitimate breaker command from the control center, proves it moved the
pandapower model, and prints the captured Modbus trace (client send + RTU
receipt) with every field L1/L2 detection will later use.
"""
from __future__ import annotations

import time

from .scada_system import ScadaSystem
from .capture import get_capture, fc_name


def _fmt_event(e) -> str:
    val = e.values if len(e.values) <= 6 else f"[{len(e.values)} values]"
    note = f"  ⟶ {e.note}" if e.note else ""
    return (f"  {e.ts_iso}  {e.capture_point:6s}  {e.src:16s} -> {e.dst:7s} "
            f"unit={e.unit_id} FC{e.function_code:<2d} {fc_name(e.function_code):22s} "
            f"addr={e.address} cnt={e.count} val={val} ok={e.ok}{note}")


def run(target_rtu: str = "rtu-21", target_line: int = 26) -> int:
    cap = get_capture()
    sysm = ScadaSystem(tick_hz=4.0)
    print("=" * 96)
    print("PHASE 2 — SCADA layer: legitimate operator command round-trip")
    print("=" * 96)
    sysm.start()
    time.sleep(1.0)

    print("\n[RTU farm online] real Modbus/TCP servers, one per substation:")
    for e in sysm.endpoints():
        g = f" gen{e['gen_id']}" if e['gen_id'] is not None else ""
        print(f"    {e['rtu_id']}  unit={e['unit_id']}  {e['host']}:{e['port']}  "
              f"lines={e['lines']}{g}")

    # 1) Poll cycle — exercises FC 4 (input regs), FC 3 (holding), FC 2 (discretes)
    print(f"\n[poll] control center polls {target_rtu} (FC4 analog, FC3 setpoints, FC2 breakers):")
    d = sysm.control.poll_rtu(target_rtu)
    print(f"    bus {d['bus']}: vm={d['vm_pu']:.3f} pu  f={d['freq_hz']:.3f} Hz")
    for ln in d["lines"]:
        print(f"      line {ln['line_id']}: P={ln['p_mw']:.1f} MW  loading={ln['loading_pct']:.1f}%  "
              f"breaker={'CLOSED' if ln['breaker_closed'] else 'OPEN'}")

    # snapshot grid state before the command
    before_closed = next(l.breaker_closed for l in sysm.engine.snapshot.lines if l.line_id == target_line)
    before_max = sysm.engine.snapshot.max_line_loading_percent

    # 2) Legitimate breaker command (FC 5 write_coil) — clear capture to isolate the round-trip
    cap.clear()
    print(f"\n[command] operator OPENS breaker on line {target_line} via {target_rtu} (FC5 write_coil)")
    sysm.control.operate_breaker(target_rtu, target_line, close=False)

    # watch the grid apply it (capture the engine event on the tick it happens)
    applied_event = None
    deadline = time.time() + 3.0
    while time.time() < deadline:
        snap = sysm.engine.snapshot
        for ev in snap.events:
            if f"line {target_line} breaker OPENED" in ev:
                applied_event = ev
        now_closed = next(l.breaker_closed for l in snap.lines if l.line_id == target_line)
        if not now_closed:
            break
        time.sleep(0.05)

    # one more poll so the RTU-side read reflects the new state too
    time.sleep(0.4)
    d2 = sysm.control.poll_rtu(target_rtu)

    after = sysm.engine.snapshot
    after_closed = next(l.breaker_closed for l in after.lines if l.line_id == target_line)
    after_max = after.max_line_loading_percent

    # 3) Also exercise FC 6, FC 15, FC 16 so the full required code set is shown
    print("[command] additionally exercising FC6/FC15/FC16 (setpoint + multi writes):")
    sysm.control.set_generator_setpoint("rtu-32", 560.0)          # FC6
    sysm.control.operate_breakers_multi("rtu-15", [True, True, True, True, True])  # FC15
    from . import rtu_map as rm
    sysm.control.set_setpoints_multi("rtu-32", [rm.enc_mw(560.0), rm.enc_tap(0)])  # FC16
    time.sleep(0.3)

    # 4) The captured trace of the round-trip
    print("\n[captured Modbus trace — the legitimate command round-trip]")
    print("  (client = control-center send with source identity; rtu = server-side wire receipt)")
    for e in cap.events():
        print(_fmt_event(e))

    # 5) Prove grid effect
    print("\n[grid effect]")
    print(f"    line {target_line} breaker: {'CLOSED' if before_closed else 'OPEN'} "
          f"-> {'CLOSED' if after_closed else 'OPEN'}")
    print(f"    engine event: {applied_event}")
    print(f"    RTU-reported breaker for line {target_line} after command: "
          + str(next((l['breaker_closed'] for l in d2['lines'] if l['line_id'] == target_line), '?')))
    print(f"    max line loading: {before_max:.1f}% -> {after_max:.1f}% (flows redistributed)")

    fcs = sorted(set(e.function_code for e in cap.events(capture_point="rtu")))
    required = {3, 4, 5, 6, 15, 16}
    print(f"\n[function codes on the wire] server-observed: {fcs}")
    print(f"    required {sorted(required)} present: {required.issubset(set(fcs))}")

    ok = (before_closed and not after_closed) and required.issubset(set(fcs))
    print("\n  VERDICT:", "PASS — real Modbus command moved the grid; full FC set captured."
          if ok else "CHECK — see output above.")
    sysm.stop()
    time.sleep(0.3)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(run())
