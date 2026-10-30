# GRIDSENTINEL

Demo-scale platform that detects and contains a cyberattack moving from a
phishing email → corporate network → IT/OT boundary → SCADA → physical power
grid, and stops it using **physics, not just signatures**.

Built for a hackathon (Critical Infrastructure & Blackout track). This is a
runnable local demo, not a production system. Everything runs on localhost
against a **simulated** grid and simulated RTUs — no real ICS/SCADA hardware,
IP ranges, or protocols are ever targeted.

## Status
Phases 1 (grid), 2 (SCADA), 3 (attack harness), 4 (L0/L1 detection), and 5
(L2/L3 detection) complete. See `CLAUDE.md` for live build state and
`GRIDSENTINEL_build_prompt.md` for the full 8-phase plan.

**Headline result (Phase 5):** the stealthy False Data Injection attack (#6)
**evades** the conventional chi-square bad-data test (J=0.0 ≪ threshold 125.5)
yet is **caught** by the trusted-PMU cross-check (4.57° state error at the target
bus). Run `python scripts/run_demo.py --detect-l2l3` to see it.

## Setup

### Option A — Docker (recommended)
```bash
docker compose build
docker compose run --rm tests                    # run the test suite
docker compose run --rm gridsentinel python scripts/run_demo.py --attack fdia
docker compose up gridsentinel                   # live API + WS on http://localhost:8000
```

### Option B — local venv
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run (Phase 1)
```bash
# 1. Live grid loop — streams bus/line/freq/loading state to the console
python scripts/run_demo.py --grid-only --ticks 10 --fast

# 2. Trip test — forces the most cascade-prone line open and shows the grid
#    react with an emergent overload cascade (not scripted)
python scripts/run_demo.py --trip-test

# 3. SCADA layer — real Modbus/TCP RTUs + control center; shows a legitimate
#    operator command (FC5) moving the pandapower model, with the captured trace
python scripts/run_demo.py --scada

# 4. Attack harness — 7 scenarios, each standalone-triggerable
python scripts/run_demo.py --list-attacks
python scripts/run_demo.py --attack fdia     # the stealthy FDIA (evades chi-square)
python -m attacks.fdia                        # or invoke directly
#   phishing malware boundary replay setpoint fdia hmi_blind

# 5. Detection (Phase 4) — run attacks 1-3 through L0/L1 detectors, show events
python scripts/run_demo.py --detect-demo

# 6. Detection (Phase 5) — attacks 4-7 through L2/L3; the FDIA proof point
python scripts/run_demo.py --detect-l2l3

# 7. Live API + WebSocket feed (for the frontend, Phase 7)
python scripts/run_demo.py --api --port 8000
#   GET  http://127.0.0.1:8000/state
#   GET  http://127.0.0.1:8000/topology
#   WS   ws://127.0.0.1:8000/ws
#   POST http://127.0.0.1:8000/control/trip/26   # drive a cascade live

# Tests
python -m pytest tests/ -v
```

## What Phase 1 gives you
- IEEE 39-bus New England case in `pandapower`, AC power flow in a loop.
- Overload protection that trips breakers after N consecutive over-rating ticks,
  letting cascades **emerge** from local logic rather than being scripted.
- A `GridSnapshot` data feed (buses, lines, trafos, gens, loads, frequency,
  loading, breaker states, per-tick events) over HTTP + WebSocket.
- Fail-open design: a diverged solve, a bad tick, or a broken subscriber never
  takes the grid loop down.

> **Note on frequency:** pandapower steady-state power flow has no dynamics, so
> `frequency_hz` is a demo-grade proxy derived from slack-bus injection
> deviation (generation loss → slack picks up → frequency dips). It moves in the
> physically correct direction on disturbances and is labelled as a proxy
> throughout.

## Architecture (target, across all phases)
```
grid/       pandapower model + power-flow loop + protection   [Phase 1 ✓]
scada/      pymodbus control center + RTU simulators           [Phase 2 ✓]
attacks/    7 attack scenarios, one file per class             [Phase 3 ✓]
detect/     L0 entry, L1 boundary, L2 protocol, L3 physics     [Phase 4-5 ✓]
correlate/  networkx attack graph + incident engine           [Phase 6]
respond/    containment ladder + DC-OPF load shed              [Phase 6]
api/        FastAPI + WebSocket                                [Phase 1 ✓ / grows]
frontend/   React + D3 dashboard                               [Phase 7]
```
