# GRIDSENTINEL — Build Prompt for Claude Code

Paste this whole document as your first message in Claude Code, in an empty
project folder. It defines the mission, the constraints, and eight phases.
Work through the phases **in order**. After each phase, stop, show me what
you built and how you verified it against that phase's "Definition of done,"
and wait for me to say "continue" before starting the next one. Do not
silently skip a phase's acceptance checks to save time.

---

## 0. Mission

Build **GRIDSENTINEL**: a demo-scale platform that detects and contains a
cyberattack that moves from a phishing email, through a corporate network,
across an IT/OT boundary, into a SCADA network, and finally into a physical
power grid — and stops it using physics, not just signatures.

This is for a hackathon (Critical Infrastructure & Blackout track). The
deliverable is a **runnable local demo**, not a production system: a live
grid simulation, a SCADA layer, seven attack scenarios, five detection
layers, and a dashboard that shows a split-screen "defended vs undefended"
demo with real numbers.

Judge on: does the physics-based detection layer actually catch a false
data injection attack that a conventional bad-data test misses? Does the
whole chain — phishing to breaker — show up as one correlated incident? Is
there a visible, working containment action with a computed MW impact?
Those three things matter more than anything else in this spec.

## 1. Non-negotiable constraints

Follow these throughout, in every phase, without being reminded:

- **Simulated network only.** Every attack scenario must execute exclusively
  against our own simulated grid and our own simulated RTUs, defined inside
  this repo. Never build anything that could function against real SCADA/ICS
  hardware, real IP ranges, or real protocol implementations outside the
  sandbox. If a request ever implies otherwise, stop and ask me first.
- **Passive by default.** The detection/sensor path reads network and
  process data; it does not write to the simulated process network except
  through the explicit, clearly-labeled containment actions built in Phase 6.
- **Fail open.** If any detector or the correlation engine crashes, the grid
  simulation keeps running exactly as it would with no security layer
  attached. A detector must never be able to take down the grid sim itself.
- **Explainable verdicts.** Every alert must carry the specific rule,
  threshold, or residual value that fired — never a bare "anomaly detected."
- **No secrets, no telemetry, no real credentials anywhere in the repo.**
  Everything runs on localhost with dummy config.

## 2. Tech stack (pinned — don't substitute without telling me)

- **Grid simulation:** Python, `pandapower`, IEEE 39-bus New England case,
  AC power flow, running as a loop (target 1 Hz, slower is fine for a demo).
- **SCADA / protocol layer:** Python, `pymodbus`, real Modbus/TCP between a
  simulated control center process and simulated RTU processes.
- **Detection:**
  - L0/L1 (entry vector, boundary): `scikit-learn` (gradient boosting,
    IsolationForest), simple rule-based feature checks.
  - L2 (protocol): `hmmlearn` or a hand-rolled Markov model, plus explicit
    allowlists.
  - L3 (physics): `pandapower.estimation` weighted least squares, SciPy,
    a chi-square residual test, plus a held-out "trusted" PMU subset for
    cross-validation.
  - L4 (correlation): `networkx` for the attack graph.
- **Backend:** `FastAPI` + WebSocket for push updates. SQLite for storage.
- **Frontend:** React + `D3.js` for the one-line diagram and attack graph.
  Plain CSS or Tailwind, dark UI.
- **Everything else:** stdlib where possible. Keep dependencies minimal and
  justify any addition outside this list before installing it.

## 3. Repo structure to set up in Phase 0

```
gridsentinel/
  grid/            # pandapower model, power flow loop, topology
  scada/           # Modbus control center + RTU simulators
  attacks/         # attack scenario scripts, one file per attack class
  detect/
    l0_entry/
    l1_boundary/
    l2_protocol/
    l3_physics/
  correlate/       # attack graph + incident engine
  respond/         # containment actions, DC-OPF load shed
  api/             # FastAPI app, WebSocket handlers
  frontend/        # React app
  scripts/         # run_demo.py, seed data, etc.
  tests/
  README.md
  CLAUDE.md        # short pointer back to this build plan + current phase
```

Keep `CLAUDE.md` updated at the end of every phase with: what's built, what
commands run it, what's left. That file is how a future session (mine or
yours) picks the project back up without re-reading this whole prompt.

---

## Phase 1 — Grid alive

**Goal:** A physically real, continuously running grid simulation that the
rest of the system can attach to, with a data feed a frontend could render.

**Build:**
- Load the IEEE 39-bus New England case in `pandapower`.
- Run AC power flow in a loop, publishing bus voltages, line flows, breaker
  states, generator output, load, and frequency at each tick.
- Add simple overload protection logic: a line or transformer exceeding its
  rating for N consecutive ticks trips its breaker. Let cascades emerge from
  this logic rather than being scripted.
- Expose the live state over a local API/WebSocket (`grid/` talks to `api/`).
- Write a script that forces a line trip manually, and confirms the
  simulation reacts (recalculates flows, trips adjacent overloaded elements
  if applicable).

**Definition of done:**
- `python scripts/run_demo.py --grid-only` starts the grid loop and prints
  live bus/line state to the console or a log file.
- A manual trip test shows a believable local cascade (not a crash, not a
  no-op).
- Unit test confirms power balance holds (generation ≈ load + losses) in
  steady state.

Stop here and show me the running loop and the trip test before continuing.

---

## Phase 2 — SCADA layer

**Goal:** Real Modbus/TCP traffic between a control center and RTUs, wired
to the grid simulation, so later phases have real protocol frames to attack
and detect against.

**Build:**
- One `pymodbus` server per substation/RTU (start with 5–8 of the 39 buses
  as instrumented RTUs — don't wire up all 39 unless it's easy).
- Each RTU exposes: measured bus voltage/line flow as input registers,
  breaker status as a discrete input, breaker open/close and setpoint
  writes as coils/holding registers.
- A control-center client (`scada/`) that polls all RTUs on a cycle and can
  issue legitimate operator commands (open/close breaker, change a
  setpoint) that actually affect the `pandapower` model.
- A packet-capture hook (even a simple in-process log of every Modbus
  request/response) that later detection layers can read from — this is
  your substitute for a real network tap.

**Definition of done:**
- Running the control-center client shows real Modbus function codes
  (3, 4, 5, 6, 15, 16) on the wire, not a mocked abstraction.
- Issuing a legitimate breaker command from the control center changes the
  grid simulation state and that change is visible in Phase 1's live feed.
- Captured traffic log has enough fields (source, dest, function code,
  register, value, timestamp) for L2 detection to use later.

Stop here and show me a captured trace of a legitimate command round-trip.

---

## Phase 3 — Attack harness

**Goal:** Seven independently-triggerable attack scenarios, each documented
with what it does and which layer should eventually catch it.

**Build one script per class, all inside `attacks/`, all attacking only your
own simulated network from Phase 1/2:**

1. **Phishing delivery** — a synthetic email dataset entry (not a live send)
   that a mail classifier will later score. No live email involved.
2. **Malware execution** — a simulated "workstation" process whose behavior
   (process spawn pattern, beacon timing) L0 will later model. Doesn't need
   real malware — simulate the *signal*, e.g. a script that spawns child
   processes in a suspicious ancestry pattern and beacons on an interval.
3. **Unauthorized boundary traversal** — a script that opens a Modbus
   session from a host/port pair your baseline hasn't seen before, at an
   off-hours timestamp.
4. **Unauthorized breaker operation (replay)** — capture a legitimate
   command from Phase 2 and replay it out of context.
5. **Setpoint / tap-changer manipulation** — write an out-of-band value to
   a generator setpoint or tap changer via Modbus, bypassing rate limits.
6. **False data injection (FDIA)** — craft a measurement vector that lies in
   the column space of the state-estimation Jacobian, so a conventional
   residual test doesn't flag it. This is the one that matters most —
   spend real time getting it right, and write down in code comments
   exactly how the crafted vector evades the naive chi-square test.
7. **Manipulation of view / HMI blinding** — report stale/nominal values to
   the control center while the real simulated state diverges.

**Definition of done:**
- Each attack has a `run(...)` entry point that can be triggered standalone
  from a CLI flag, e.g. `python -m attacks.fdia --target rtu-07`.
- Each attack script prints/logs what it changed and why it should be hard
  to catch without the corresponding detection layer.
- Attack 6 (FDIA) specifically: write a short test that runs a
  conventional WLS + chi-square check against it and confirms the
  conventional check **passes** (i.e., the attack succeeds against naive
  detection). This is the baseline Phase 5 has to beat.

Stop here. This phase is the foundation for every detection phase after
it — don't let it be half-finished.

---

## Phase 4 — Detection layers L0 and L1 (entry vector, boundary)

**Goal:** Catch attacks 1–3 from Phase 3.

**Build:**
- L0 mail: feature-engineer a small synthetic/public phishing dataset
  (headers, URL lexical features, attachment macro flags), train a
  gradient-boosted classifier, score attack #1's sample.
- L0 endpoint/malware: rule-based + IsolationForest over process-ancestry
  and beacon-timing features from attack #2's simulated signal.
- L1 boundary: baseline "normal" host-pair/protocol/hour tuples from Phase
  2's legitimate traffic, then flag first-seen pairs and off-hours sessions
  — this should catch attack #3.
- Every detector writes a structured event (source, detector, confidence,
  evidence) to a shared event store/bus that Phase 6's correlator will
  read from later. Build this event schema carefully now — everything
  downstream depends on it.

**Definition of done:**
- Running attacks 1–3 each produces at least one detection event with a
  confidence score and a human-readable reason.
- Running normal/legitimate traffic from Phase 2 does **not** produce
  detection events above your alert threshold (spot-check false positive
  rate informally — a rigorous number can wait).

Stop here and show me one detection event JSON/log line per attack class.

---

## Phase 5 — Detection layers L2 and L3 (protocol, physics) — the core

**Goal:** Catch attacks 4–7. This is the differentiator. Do not rush it.

**Build:**
- L2 protocol: per-RTU function-code allowlist (a read-only RTU should
  never accept a write), a sequence model over command order, and a
  write-rate ceiling. Should catch attacks 4 and 5.
- L3 physics — the important part:
  - Run WLS state estimation on every measurement cycle using
    `pandapower.estimation`, with a chi-square residual test as the
    conventional baseline (this is what attack #6, FDIA, is built to
    evade — confirm it still evades it here).
  - Add the **trusted PMU subset cross-check**: hold out a small set of
    measurements as "trusted" (not visible to the attacker's crafted
    vector), and independently verify the estimator's solution against
    them. This is what should catch attack #6 where the naive test fails.
  - Add breaker–flow consistency: a line reporting nonzero flow while its
    breaker reports open is a hard-fail regardless of what the estimator
    says.
  - Add a topology/plausibility check against the last known-good trusted
    state, to help catch attack #7 (HMI blinding / manipulation of view).
- Same event schema as Phase 4 — L2/L3 detections go to the same store.

**Definition of done:**
- Attack #6 (FDIA) is caught by the trusted-subset cross-check even though
  the code confirms it still evades the naive chi-square test. Write an
  explicit test asserting this: naive test passes (attack succeeds against
  it), full L3 check catches it (attack fails against it). This contrast
  is the single most important proof point in the whole project.
- Attacks 4, 5, 7 each produce a detection event with the specific rule or
  residual that fired.
- A detection latency measurement exists for at least attack #6 (even
  informal — "N simulation ticks from injection to detection").

Stop here. Walk me through the FDIA test result specifically before moving
on — this is the slide judges will ask about.

---

## Phase 6 — Correlation and response

**Goal:** Turn scattered detection events into one incident, and act on it.

**Build:**
- `correlate/`: a `networkx` directed graph where each detection event
  becomes a node; edges connect plausibly-related events across time and
  asset adjacency (e.g., the host that sent a phishing-flagged mail later
  appears as the source of a boundary-traversal event).
- A scoring/promotion rule: when any node in a connected component reaches
  a physics-confirmed (L3) verdict, promote the whole component to a
  single incident record with a start time, entry point, and path.
- `respond/`: a containment ladder —
  1. Isolate the offending RTU's write path (stop accepting writes from it
     at the simulated boundary).
  2. Revert the control center's displayed state to the last trusted
     estimate.
  3. Compute minimum load shed via DC-OPF (`pandapower` has this) to clear
     any active overload, ranked so a configurable "protected" feeder list
     (e.g., hospital/water) sheds last.
  4. Export the incident as a structured record (timeline + evidence +
     MW impact) — this is your "audit artifact."
- Operator-in-the-loop: proposed actions are logged with predicted MW
  impact and require an explicit accept before Phase 1's grid model is
  actually modified. Autonomous execution is a flag, off by default.

**Definition of done:**
- Running the full attack chain (phishing → ... → attack #6 or #7) end to
  end produces exactly one incident record referencing every relevant
  earlier event, not N separate unrelated alerts.
- The containment ladder, once accepted, measurably changes the grid
  simulation (isolates the RTU, and if load shed was proposed, sheds the
  computed amount and clears the overload).
- The exported incident record is a real file/JSON you can open and read.

Stop here and show me one full incident record end to end.

---

## Phase 7 — Frontend / dashboard

**Goal:** The three operator views from the pitch deck, backed by real data
from Phases 1–6 (no mocked numbers).

**Build:**
- **Grid operations view:** live one-line diagram (D3), bus voltage color
  coding, tripped elements highlighted, a small system strip (frequency,
  load, margin, state).
- **Kill chain view:** the attack graph from Phase 6 rendered as nodes/edges
  with a timeline scrubber; scrubbing shows what was known at that instant.
- **Response view:** the containment ladder with predicted MW impact per
  action, protected-feeder list, accept/reject controls wired to Phase 6.
- Wire all three to the FastAPI WebSocket feed — this should be live, not
  a static screenshot.

**Definition of done:**
- Opening the frontend against a running backend shows the grid updating
  in near-real-time.
- Triggering an attack from a CLI or a demo control in the UI visibly
  updates all three views within a few seconds.
- No hardcoded/fake numbers remain in the frontend — everything traces to
  a real backend value.

Stop here and demo the live loop to me before the final phase.

---

## Phase 8 — Demo mode and metrics

**Goal:** The actual thing you'll show the judges.

**Build:**
- A "split screen" demo mode: two instances of the grid+attack pipeline,
  one with detection/response disabled, one with it enabled, both driven
  by the identical attack script simultaneously, with live MW-lost
  counters on each side.
- A metrics script that runs each of the 7 attacks N times and reports,
  per class: detection rate, false positive rate on a legitimate-traffic
  control run, and time-to-detect. Report real measured numbers — do not
  reuse the target thresholds from the pitch deck as if they were results.
- A one-command demo launcher (`scripts/run_demo.py --full`) that starts
  everything needed for the live presentation.
- Update `README.md` with exact setup/run instructions a judge or teammate
  could follow cold.

**Definition of done:**
- The split-screen demo runs start-to-finish from one command.
- The metrics script produces a real table of numbers, and you can tell me
  honestly where they fall short of the pitch deck's target thresholds.
- A teammate who didn't write any of this code can follow the README and
  get the demo running.

---

## How to work each phase

For every phase: propose your file/module plan briefly before writing
significant code, then build it, then run the Definition of done checks
yourself and show me the actual output (terminal logs, test results, not
just "it should work"). If a Definition of done item fails, fix it before
telling me the phase is complete — don't move to the next phase with a
known-broken foundation. If you hit a design decision not covered by this
spec, make a reasonable call, tell me what you chose and why in one or two
sentences, and keep going rather than stopping to ask, unless it touches
the constraints in Section 1 — those you always check with me first.

## Handling extra features I ask for mid-build

I will sometimes ask for something not in this spec while you're in the
middle of a phase — a new attack scenario, a UI touch, an integration, a
change to something you already built. Treat every one of these as a
**request to classify and slot in**, not as an interruption to drop
everything for for. Each time this happens:

1. **Classify it before building anything:**
   - **Fits inside the current phase's scope** (e.g. I ask for an eighth
     attack class while you're in Phase 3) → build it now, alongside the
     phase's existing checklist, and add it to that phase's Definition of
     done before you call the phase complete.
   - **Belongs to a later phase** (e.g. I ask for a metrics dashboard while
     you're in Phase 2) → don't build it now. Add it as a bullet under that
     phase's "Build" list in `CLAUDE.md` so it isn't forgotten, tell me
     you've queued it and for which phase, and stay on the current phase.
   - **Is genuinely new scope that doesn't fit any existing phase** (e.g. I
     ask for a mobile view, or an integration with something outside this
     spec) → propose in one or two sentences where it should go: its own
     phase inserted at a specific point, or an add-on after Phase 8. Wait
     for me to confirm the placement before building anything nontrivial for
     it. A trivial one-file addition doesn't need this — use judgment.
   - **Conflicts with a constraint in Section 1 or with something already
     built** → flag the conflict explicitly and check with me before
     proceeding, same as any Section 1 conflict.

2. **Log it.** Keep a running `## Ad-hoc additions` section in `CLAUDE.md`
   listing what was requested, which phase it landed in (or was queued
   for), and its status (done / queued / needs confirmation). This is what
   keeps a feature you mention once from silently vanishing three phases
   later.

3. **Don't let it break a phase gate.** A mid-phase addition never counts as
   completing the phase's own Definition of done, and it never becomes a
   reason to wave through a check that's still failing. If a request is big
   enough that it would meaningfully delay the current phase's completion,
   say so and let me decide whether it jumps the queue or waits.

4. **Small asks, just do them.** Not everything needs the full
   classification dance — a copy change, a color tweak, a config value,
   a one-line fix. Use judgment on what's "small"; when in doubt, say which
   bucket you put it in and move on rather than asking permission for
   something trivial.
