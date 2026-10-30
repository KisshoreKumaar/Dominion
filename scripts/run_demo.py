"""GRIDSENTINEL demo launcher.

Phase 1 surface:
  python scripts/run_demo.py --grid-only [--ticks N] [--hz HZ] [--fast]
      Start the grid loop and print live bus/line state to the console.

  python scripts/run_demo.py --trip-test [--trip-line ID]
      Run the grid to steady state, force a line breaker open, and show the
      simulation react (flow redistribution + any emergent cascade).

Later phases add --scada, --full, etc. Kept dependency-light so it runs with
just the Phase 1 stack (pandapower).
"""
from __future__ import annotations

import argparse
import os
import sys

# Allow "python scripts/run_demo.py" to import the top-level packages.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from grid.engine import GridEngine  # noqa: E402


def cmd_grid_only(args) -> int:
    print(f"[grid-only] loading IEEE 39-bus case, tick rate {args.hz} Hz, "
          f"protection: >{args.threshold:.0f}% for {args.pickup} ticks")
    engine = GridEngine(tick_hz=args.hz, pickup_ticks=args.pickup,
                        threshold_percent=args.threshold)
    print(engine.snapshot.summary_line())

    def on_tick(snap):
        print(snap.summary_line())

    try:
        engine.run(ticks=args.ticks, realtime=not args.fast, on_tick=on_tick)
    except KeyboardInterrupt:
        print("\n[grid-only] stopped by user")
    return 0


def cmd_trip_test(args) -> int:
    """Force a line trip and confirm the grid reacts (not a crash, not a no-op)."""
    engine = GridEngine(tick_hz=args.hz, pickup_ticks=args.pickup,
                        threshold_percent=args.threshold)

    print("=" * 78)
    print("TRIP TEST — forcing a line breaker open and watching the grid react")
    print("=" * 78)

    # Warm up to a stable steady state.
    for _ in range(3):
        engine.step()
    pre = engine.snapshot
    print("\n[steady state before trip]")
    print(pre.summary_line())
    print(f"  lines in service: {sum(1 for l in pre.lines if l.breaker_closed)}"
          f" / {len(pre.lines)}   max line loading: {pre.max_line_loading_percent:.1f}%")

    # Choose the line to trip. By default we scan every single-line outage and
    # pick the one that most stresses the *rest* of the grid (without simply
    # islanding a load pocket) — that is the outage that produces an emergent
    # cascade. Overridable with --trip-line.
    if args.trip_line is not None:
        target = args.trip_line
    else:
        from grid import model
        target, projected = model.worst_n1_line(engine.net)
        print(f"\n[N-1 scan] most cascade-prone outage: line {target} "
              f"(projected to push a neighbour to {projected:.1f}% loading)")
    tline = next(l for l in pre.lines if l.line_id == target)
    print(f"\n>>> Forcing OPEN breaker on line {target} "
          f"(bus {tline.from_bus}->{tline.to_bus}, was {tline.loading_percent:.1f}% loaded)")

    engine.trip_line(target, reason="trip-test manual command")

    # Run several ticks and report every state change / event.
    print("\n[grid response, tick by tick]")
    tripped_before = set(pre.tripped_lines())
    for _ in range(8):
        snap = engine.step()
        newly = set(snap.tripped_lines()) - tripped_before
        marker = "  <-- CASCADE" if newly - {target} else ""
        print("  " + snap.summary_line() + marker)
        for ev in snap.events:
            print(f"        · {ev}")
        tripped_before = set(snap.tripped_lines())

    post = engine.snapshot
    print("\n[result]")
    tripped = post.tripped_lines()
    print(f"  converged: {post.converged}")
    print(f"  lines tripped total: {len(tripped)} -> {tripped}")
    print(f"  max line loading now: {post.max_line_loading_percent:.1f}%")
    print(f"  frequency proxy: {pre.frequency_hz:.3f} Hz -> {post.frequency_hz:.3f} Hz")

    # Verdict: reacted (flows changed and grid still solving) vs no-op/crash.
    reacted = post.converged and (len(tripped) >= 1)
    changed = abs(post.max_line_loading_percent - pre.max_line_loading_percent) > 0.01
    if reacted and changed:
        print("\n  VERDICT: PASS — breaker opened, flows redistributed, sim still solving.")
        if len(tripped) > 1:
            print(f"           Emergent cascade: {len(tripped)-1} additional element(s) tripped on overload.")
        return 0
    print("\n  VERDICT: CHECK — expected a reaction; inspect output above.")
    return 1


def cmd_scada(args) -> int:
    from scada.demo import run as scada_demo
    return scada_demo()


def cmd_list_attacks(args) -> int:
    from attacks.harness import list_attacks
    print("GRIDSENTINEL attack harness — 7 scenarios:")
    for a in list_attacks():
        print(f"  #{a['class']}  {a['name']:10s} {a['title']:44s} -> {a['layer']}")
    print("\nrun one with:  python scripts/run_demo.py --attack <name>")
    print("        or:    python -m attacks.<name>")
    return 0


def cmd_attack(args) -> int:
    from attacks.harness import run_attack
    result = run_attack(args.attack)
    result.print_report()
    return 0 if result.executed else 1


def cmd_detect_demo(args) -> int:
    from detect.demo import run as detect_demo
    return detect_demo()


def cmd_detect_l2l3(args) -> int:
    from detect.demo import run_phase5
    return run_phase5()


def cmd_api(args) -> int:
    print(f"[api] starting GRIDSENTINEL live feed on http://127.0.0.1:{args.port}")
    print("      GET /state  ·  GET /topology  ·  WS /ws  ·  POST /control/trip/{line_id}")
    import uvicorn
    from api.app import app
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="GRIDSENTINEL demo launcher")
    p.add_argument("--grid-only", action="store_true",
                   help="run the grid loop and stream live state")
    p.add_argument("--scada", action="store_true",
                   help="bring up the SCADA layer and show a legitimate command round-trip")
    p.add_argument("--list-attacks", action="store_true",
                   help="list the 7 attack scenarios")
    p.add_argument("--attack", type=str, default=None,
                   help="run one attack by name (phishing|malware|boundary|replay|setpoint|fdia|hmi_blind)")
    p.add_argument("--detect-demo", action="store_true",
                   help="Phase 4: run attacks 1-3 through L0/L1 detectors, show events")
    p.add_argument("--detect-l2l3", action="store_true",
                   help="Phase 5: run attacks 4-7 through L2/L3, show the FDIA proof point")
    p.add_argument("--api", action="store_true",
                   help="serve the live grid state over HTTP + WebSocket")
    p.add_argument("--port", type=int, default=8000, help="API port")
    p.add_argument("--trip-test", action="store_true",
                   help="force a line trip and show the grid react")
    p.add_argument("--ticks", type=int, default=None,
                   help="number of ticks to run in --grid-only (default: forever)")
    p.add_argument("--hz", type=float, default=1.0, help="tick rate (Hz)")
    p.add_argument("--fast", action="store_true",
                   help="ignore realtime pacing; run ticks back-to-back")
    p.add_argument("--pickup", type=int, default=3,
                   help="consecutive over-rating ticks before a breaker trips")
    p.add_argument("--threshold", type=float, default=100.0,
                   help="loading percent that counts as an overload")
    p.add_argument("--trip-line", type=int, default=None,
                   help="line id to trip in --trip-test (default: most loaded)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.trip_test:
        return cmd_trip_test(args)
    if args.grid_only:
        return cmd_grid_only(args)
    if args.scada:
        return cmd_scada(args)
    if args.list_attacks:
        return cmd_list_attacks(args)
    if args.attack:
        return cmd_attack(args)
    if args.detect_demo:
        return cmd_detect_demo(args)
    if args.detect_l2l3:
        return cmd_detect_l2l3(args)
    if args.api:
        return cmd_api(args)
    print("nothing to do — pass --grid-only, --trip-test, --scada, --attack, or --api (see --help)")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
