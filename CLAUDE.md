# GRIDSENTINEL — build state

Pointer file for future sessions. Full plan: `GRIDSENTINEL_build_prompt.md`.

## Current phase
**Phase 5 (Detection L2/L3) — COMPLETE, awaiting user sign-off before Phase 6.**
(Phases 1-4 signed off. Project is Dockerized — see below.)

## What's built
- **Repo skeleton** for all phases (`grid scada attacks detect/{l0..l3} correlate
  respond api frontend scripts tests`), Python packages with `__init__.py`.
- **`grid/`** — the live simulation:
  - `model.py` — loads IEEE 39-bus New England case (`pandapower.networks.case39`);
    backfills line current ratings; `run_power_flow()` (fail-open, never raises);
    `worst_n1_line()` scans single-line outages for the most cascade-prone one.
  - `state.py` — `GridSnapshot` + Bus/Line/Trafo/Gen/Load dataclasses, `to_dict()`
    for the WS feed. **This is the published schema.**
  - `protection.py` — `OverloadProtection` state machine: trips a breaker after N
    consecutive ticks over rating. Side-effect free (returns trips, caller opens).
  - `engine.py` — `GridEngine`: one AC power flow per tick, applies protection,
    emits snapshots, background-thread run loop, breaker open/close control surface,
    subscriber callbacks. **Fail-open**: bad tick / diverge / bad subscriber never
    stops the loop. Breaker = element `in_service`. Frequency = **demo-grade proxy**
    from slack-bus injection deviation (documented in engine.py).
- **`api/app.py`** — FastAPI + WebSocket live feed: `GET /`, `/state`, `/topology`,
  `POST /control/trip|close/{line_id}`, `WS /ws` (pushes every snapshot).
- **`grid/engine.py`** (extended in P2) — added `set_gen_setpoint()` and
  `set_trafo_tap()` control hooks; pending-ops are now tagged tuples.
- **`scada/`** — the SCADA layer (Phase 2):
  - `capture.py` — `CaptureBus` + `ModbusEvent` (ts, src+identity, dst, unit, FC,
    fc_name, address, count, values, tid, ok, note). Two capture points:
    `client` (control-center send, has source identity) and `rtu` (server-side
    wire receipt). SQLite persistence optional. **The tap L1/L2 read from.**
    `GLOBAL_CAPTURE` shared bus. NOTE: `CaptureBus.__len__` makes an empty bus
    falsy — always pass it with `is not None`, never `x or get_capture()`.
  - `rtu_map.py` — 8 RTUs at buses [2,15,16,20,21,22,23,32] (cascade corridor +
    gen bus 32). Identical register map per RTU (IR=analog, DI=breaker status,
    CO=breaker cmd, HR=setpoints). Ports 5020-5027, unit ids 1-8. Encode/decode
    helpers (offset-encoded MW, scaled pu/Hz/loading). `build_rtu_specs(net)`.
  - `rtu_server.py` — `CapturingSlaveContext` (subclasses pymodbus
    `ModbusSlaveContext`; overrides getValues/setValues to capture FC + bridge
    writes to the engine). `RTUServer` (one TCP server/port), `RTUFarm` (runs all
    servers + measurement updater on an asyncio loop in a bg thread). IMPORTANT:
    base context adds +1 to every address — always go through base methods
    (`_raw_set`), never `self.store` directly.
  - `control_center.py` — `CapturingModbusClient` (wraps pymodbus TCP client,
    logs source identity) + `ControlCenter` (poll_all, operate_breaker[FC5],
    set_generator_setpoint[FC6], operate_breakers_multi[FC15],
    set_setpoints_multi[FC16], background poll loop).
  - `scada_system.py` — `ScadaSystem` ties engine+farm+control together.
  - `demo.py` — Phase 2 command round-trip demo (used by `--scada`).
- **`grid/engine.py`** (extended in P3) — `restore_base()` resets to clean base
  (all breakers closed, gen setpoints nominal, protection reset, re-solved) for
  attack recovery / demo repeatability. Also `set_frozen` path via RTU (attack #7).
- **`detect/l3_physics/estimator.py`** (built in P3, used by FDIA + Phase 5) —
  conventional WLS state estimation + chi-square residual test. `StateEstimator`,
  `measurements_from_powerflow`, measurement-set dicts. The baseline the FDIA evades.
- **`detect/` — L0/L1 detection (Phase 4):**
  - `events.py` — **ARCHITECTURE-CRITICAL** `DetectionEvent` schema + `EventStore`
    (in-mem + SQLite, subscribe). Fields: detector, layer, attack_stage, title,
    explainable `reason`, confidence, severity, `entities` (hosts/RTUs/mailboxes
    for Phase 6 correlation), evidence, assets. `GLOBAL_EVENTS`. **Phase 6 reads this.**
  - `l0_entry/mail.py` — synthetic phishing dataset + GradientBoosting classifier;
    `MailClassifier.detect()`, `benign_email_sample()`. Catches attack #1.
  - `l0_entry/endpoint.py` — office->shell ancestry rule + IsolationForest over
    beacon-timing/process features; `EndpointDetector`, `benign_endpoint_signal()`.
    Catches attack #2.
  - `l1_boundary/boundary.py` — `BoundaryBaseline` (learns known src/pairs/hours
    from legit capture) + `BoundaryDetector` (first-seen host-pair + off-hours).
    Reads the capture bus. Catches attack #3.
  - `l2_protocol/protocol.py` (Phase 5) — `ProtocolBaseline` + `ProtocolDetector`:
    FC allowlist / write-authorization (writes only from known master), replay
    signature (non-master frame matching a master's), write-rate ceiling, and a
    first-order FC-sequence (Markov) model. Catches attacks #4 (replay) + #5 (setpoint).
  - `l3_physics/detector.py` (Phase 5) — **THE core.** `TrustedSubsetMonitor`
    (estimate from reachable meas, cross-check vs untouched trusted PMUs -> catches
    FDIA #6 that chi-square misses) + `ConsistencyMonitor` (within-RTU breaker/flow
    + cross-RTU disagreement -> catches HMI blinding #7).
  - `pipeline.py` — runs attacks 1-7 through detectors, emits events, FP checks;
    `run_l2_protocol`, `run_l3_fdia` (with latency), `run_l3_hmi`.
  - `demo.py` — Phase 4 demo (`--detect-demo`) + Phase 5 demo (`--detect-l2l3`).
  - Attacks #1/#2 enriched with shared victim identity (workstation eng-laptop-07 /
    10.0.7.66 / j.rivera) so Phase 6 can link the kill chain across L0->L1.
  - hmi_blind.run gained `leave_frozen=` so L3 can poll the corrupted view before cleanup.
- **`attacks/`** — the 7-scenario harness (Phase 3):
  - `common.py` — `AttackResult`, `@register` registry, `live_scada()` ctx mgr,
    `off_hours_timestamp()`, `cli_main()`.
  - `harness.py` — imports all 7 (populates registry), `list_attacks`, `run_attack`.
  - `phishing.py` #1 (L0 mail), `malware.py` #2 (L0 endpoint) — standalone synthetic
    signals, no grid needed.
  - `boundary.py` #3 (L1), `replay.py` #4 (L2), `setpoint.py` #5 (L2),
    `hmi_blind.py` #7 (L3) — spin up a live ScadaSystem (or take `system=`).
  - `fdia.py` #6 (L3) — **the core.** Builds a stealthy FDIA as a consistent
    alternate power-flow state (a=H·c by construction), evades naive chi-square,
    holds out trusted PMU angle measurements at buses [16,21,22] as the Phase-5 tell.
- **`scripts/run_demo.py`** — `--list-attacks`, `--attack`, `--detect-demo` (P4),
  `--detect-l2l3` (P5).
- **Docker** — `Dockerfile` (python:3.12-slim; host runs 3.14, container 3.12 for
  manylinux wheels), `docker-compose.yml` (`gridsentinel` = API service, `tests` =
  suite), `.dockerignore`, `requirements.txt` (pinned). `docker compose run --rm tests`.
- **`tests/`** — 38 tests, all green (9 grid + 6 SCADA + 10 attacks + 8 L0/L1 +
  5 L2/L3 incl. the **FDIA naive-passes-but-L3-catches** contrast). Pass in-container.

## Commands
```bash
source .venv/bin/activate
python scripts/run_demo.py --grid-only --ticks 10 --fast   # stream live state
python scripts/run_demo.py --trip-test                     # cascade demo
python scripts/run_demo.py --scada                         # SCADA command round-trip
python scripts/run_demo.py --list-attacks                  # the 7 attack scenarios
python scripts/run_demo.py --attack fdia                   # run one attack (e.g. FDIA)
python -m attacks.fdia                                     # or invoke directly
python scripts/run_demo.py --detect-demo                   # Phase 4: L0/L1 catch attacks 1-3
python scripts/run_demo.py --detect-l2l3                   # Phase 5: L2/L3 catch attacks 4-7 (FDIA proof)
python scripts/run_demo.py --api --port 8000               # live HTTP+WS feed
python -m pytest tests/ -v                                 # 38 passing

# Docker
docker compose build
docker compose run --rm tests                              # 38 passing in-container
docker compose run --rm gridsentinel python scripts/run_demo.py --attack fdia
docker compose up gridsentinel                             # live API+WS on :8000
```

## Phase 1 Definition of done — status
- [x] `run_demo.py --grid-only` starts the loop and prints live bus/line state.
- [x] Manual trip test shows a believable local cascade (line 26 → lines 23/27/28
      trip on overload; grid stays converged, settles at 96% max loading, freq dips
      to ~59.45 Hz). Auto-selected via N-1 scan, not hardcoded.
- [x] Unit test confirms power balance (gen ≈ load + losses) in steady state.
- [x] (Build-list extra) live state exposed over local API/WebSocket.

## Key design decisions
- Packages live at repo root (the `dominion/` folder IS the project); no nested
  `gridsentinel/` dir. Keeps imports clean (`from grid.engine import GridEngine`).
- Breakers modelled as `in_service` toggles (directly affect power flow).
- Frequency is a proxy (pandapower steady-state PF has no dynamics) — labelled
  everywhere it appears. Droop tuned so ~600 MW gen loss ≈ -0.5 Hz.
- `worst_n1_line()` picks the trip target dynamically so the cascade is emergent
  and honest, not a magic hardcoded line id.

## Env
- Python 3.14.5, venv at `.venv/`. Installed: pandapower 3.5.4 (+ numpy/scipy/
  pandas/networkx), fastapi, uvicorn, websockets, pytest. numba absent (PF slower
  but fine for demo).

## Phase 2 Definition of done — status
- [x] Control-center client shows real Modbus FCs 3,4,5,6,15,16 on the wire
      (server-observed [2,3,4,5,6,15,16]), not a mocked abstraction.
- [x] Legitimate breaker command (FC5) changes the grid sim and is visible in
      the GridSnapshot feed (line 26 CLOSED->OPEN, engine event, max loading
      77%->157.5%, RTU re-read confirms).
- [x] Captured traffic log carries source, dest, FC, register, value, timestamp
      (+ unit, tid, ok, decoded note) — ready for L2.

## Phase 2 design decisions / gotchas
- **pymodbus pinned to 3.8.6** (stack said just "pymodbus"). 3.15 deprecated the
  classic datastore (`ModbusDeviceContext` returns DEVICE_BUSY) mid-migration to
  an unfinished SimData API. 3.8.6 has the clean subclassable
  `ModbusSlaveContext.getValues/setValues(fc, addr, ...)` we need.
- RTUs share the GridEngine in-process (not separate OS processes). Real frames
  on real sockets is what matters for the demo + detection; separate processes
  would only add a state-sync problem. Modbus write path is the ONLY SCADA->grid
  mutation (Section 1 passive-by-default honored).
- Unified API+SCADA backend (so `/ws` shows SCADA-driven changes) is deferred to
  Phase 7 wiring; today the SCADA demo reads the same GridSnapshot feed directly.

## Phase 3 Definition of done — status
- [x] Each attack has a `run(...)` entry point, standalone-triggerable
      (`python -m attacks.<name>` and `--attack <name>`).
- [x] Each prints/logs what it changed and why it's hard to catch without the
      corresponding detection layer (AttackResult.why_hard_to_catch).
- [x] FDIA: a conventional WLS + chi-square check PASSES on the crafted vector
      (test_fdia_evades_conventional_chi2: J=0.0 << thr=125.5, not flagged) —
      the attack succeeds against naive detection. This is Phase 5's baseline to beat.

## Phase 3 design decisions / notes
- FDIA is crafted as a *consistent alternate power-flow state* (hides ~150 MW at
  bus 15). Because the falsified measurements satisfy Kirchhoff exactly, residual
  ≈ 0 and chi-square is blind; equivalently a = z_false - z_true ≈ H·c ∈ range(H)
  (Liu-Ning-Reiter stealth condition, documented in fdia.py). Trusted PMU angle
  gap at buses [16,21,22] = ~4.57° is the strong signal L3 uses in Phase 5.
- SCADA-based attacks share the engine's control surface; added `restore_base()`
  so an attack can establish a clean baseline (needed by #7 and for repeatable demos).
- All attacks hit ONLY the in-repo simulated grid/RTUs (Section 1 honored).
- Detection layers themselves are NOT built yet — that's Phase 4 (L0/L1) and
  Phase 5 (L2/L3). Phase 3 only proves each attack fires and (for FDIA) evades naive.

## Docker (ad-hoc, user-requested — new infra, not in the 8-phase plan)
- `Dockerfile` uses python:3.12-slim (host venv is 3.14; container standardizes on
  3.12 for reliable manylinux wheels across the scientific stack).
- `docker-compose.yml`: `gridsentinel` service (API on :8000, RTU ports 5020-5027),
  `tests` service. `requirements.txt` pins the stack. `.dockerignore` excludes .venv.
- Verified: 25/25 tests pass in-container; `--attack fdia` reproduces in-container.

## Phase 4 Definition of done — status
- [x] Attacks 1-3 each produce >=1 detection event with confidence + human reason:
      #1 L0.mail.gbm (p=1.00, high), #2 L0.endpoint.rules+iforest (conf 0.95, high,
      excel->cmd rule + IsolationForest outlier), #3 L1.boundary.baseline (conf 0.95,
      high, first-seen source 10.0.7.66 + off-hours 03:xx).
- [x] Legitimate traffic does NOT alert: benign email score 0.000, benign endpoint
      clean, 0 boundary FPs over 72 learned legit events.
- [x] One detection-event JSON per attack class printed by `--detect-demo`.
- [x] Shared event schema (`detect/events.py`) built carefully — Phase 6 depends on it.

## Phase 4 design decisions / notes
- Event schema carries `entities` (hosts/RTUs/mailboxes) + `attack_stage` so Phase 6
  can link events by shared asset across the kill chain. Shared victim identity
  (eng-laptop-07 / 10.0.7.66 / j.rivera) threads phishing->malware->boundary.
- L0 mail dataset is deliberately overlapping (some benign urgent/macro, some
  phishing pass SPF) so the GBM learns a boundary, not one give-away rule.
- L1 off-hours uses BOTH the learned hours AND a fixed business-hours window
  [6,22) so it's deterministic regardless of when the demo runs; the first-seen
  host-pair is the primary (always-robust) signal.
- scikit-learn==1.7.2 now installed in the venv (was only in the container image).

## Phase 5 Definition of done — status
- [x] **FDIA contrast (the key proof point):** naive chi-square PASSES
      (J=0.0 < thr=125.46, not flagged — attack succeeds vs conventional) while the
      L3 trusted-PMU cross-check CATCHES it (4.57 deg angle gap at bus 22 > 1.0 deg
      threshold, critical). Asserted in test_fdia_naive_passes_but_L3_catches.
- [x] Attacks 4,5,7 each produce an event with the specific rule/residual:
      #4 L2.protocol.replay + .allowlist; #5 L2.protocol.write_rate + .allowlist;
      #7 L3.physics.breaker_flow_xrtu (line 27: rtu-21 CLOSED@43MW vs rtu-22 OPEN@0MW).
- [x] Detection latency for #6: 1 estimation cycle (~90 ms wall).
- [x] L2/L3 events go to the same EventStore as L0/L1. 0 false positives on legit
      traffic (L2) and on a healthy view (L3 consistency).

## Phase 5 design decisions / notes
- L3 FDIA check operates on measurement-set dicts (reachable vs trusted) — the
  same artifacts attack #6 emits. HMI check operates on the control-center polled
  view (realistic EMS data). Cross-RTU consistency is the #7 catch because line 27
  is instrumented by both rtu-21 (frozen) and rtu-22 (live).
- L2 write-authorization (writes only from a known master) is the primary catch
  for #4/#5 since both originate from attacker hosts; replay signature + write-rate
  + sequence corroborate. Baseline exercises legit writes to the target RTUs so
  the FC allowlist and master-frame set are complete (no legit-write false flags).

## Next: Phase 6 — Correlation (networkx attack graph) + response (containment
   ladder, DC-OPF load shed). Reads the shared EventStore; entities already thread
   the kill chain (eng-laptop-07 / 10.0.7.66 across L0->L1; RTUs across L2/L3).

## Ad-hoc additions
- **Docker containerization** — requested during Phase 3. Done (Dockerfile,
  docker-compose.yml, .dockerignore, requirements.txt). New infra scope; logged here.
