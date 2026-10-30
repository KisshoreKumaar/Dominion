"""Attack #7 — Manipulation of view / HMI blinding.

Freezes the measurements a set of RTUs report to the control center at their
last nominal values, then drives the *real* grid into a divergent state
underneath. The operator's screen stays green — nominal voltages, healthy
loadings, breakers reported CLOSED — while the physical system is actually
cascading.

This is "manipulation of view": the process data path is lying, not the command
path. Nothing on the wire is malformed; the RTU simply reports stale-but-valid
numbers.

Target detection layer: L3 (physics) — breaker/flow consistency + plausibility
against the last known-good trusted state (a line reported CLOSED and nominal
while its neighbours' physics say otherwise is a hard fail).
"""
from __future__ import annotations

import time

from .common import AttackResult, register, cli_main, live_scada


@register("hmi_blind", attack_class=7, title="Manipulation of view / HMI blinding", layer="L3 physics")
def run(freeze_rtus=("rtu-20", "rtu-21"), divert_line: int = 26, system=None,
        leave_frozen: bool = False) -> AttackResult:
    freeze_rtus = list(freeze_rtus)
    with live_scada(system) as sysm:
        cc = sysm.control
        eng = sysm.engine

        # Establish a clean nominal baseline first, so the attacker freezes a
        # *healthy* view and the demo is repeatable regardless of prior grid state.
        eng.restore_base(reason="attack #7 baseline")
        deadline = time.time() + 3.0
        while time.time() < deadline:
            if all(l.breaker_closed for l in eng.snapshot.lines) and eng.snapshot.converged:
                break
            time.sleep(0.1)
        time.sleep(0.5)

        # baseline: what the control center sees before blinding
        pre_view = {r: cc.poll_rtu(r) for r in freeze_rtus}
        pre_line = next(l for l in eng.snapshot.lines if l.line_id == divert_line)

        # 1) BLIND: freeze the targeted RTUs at their current nominal values.
        for r in freeze_rtus:
            sysm.farm.set_frozen(r, True)
        time.sleep(0.3)

        # 2) DIVERGE: drive the real grid — open the corridor line so flows shift
        #    and neighbours overload, exactly what the operator must NOT see.
        eng.trip_line(divert_line, reason="attack #7: real divergence behind frozen HMI")
        time.sleep(1.5)   # let the real grid react / start cascading

        # 3) what the operator sees now (frozen) vs what is real
        blind_view = {r: cc.poll_rtu(r) for r in freeze_rtus}
        real_snap = eng.snapshot
        real_line = next(l for l in real_snap.lines if l.line_id == divert_line)

        # measure the divergence between reported and real for the target line
        reported_closed = None
        reported_loading = None
        for r in freeze_rtus:
            for ln in blind_view[r]["lines"]:
                if ln["line_id"] == divert_line:
                    reported_closed = ln["breaker_closed"]
                    reported_loading = ln["loading_pct"]
        real_max_loading = real_snap.max_line_loading_percent

        # unfreeze so the system is left clean for the next attack, unless the
        # caller (e.g. the L3 detector pipeline) wants to inspect the frozen view.
        if not leave_frozen:
            for r in freeze_rtus:
                sysm.farm.set_frozen(r, False)

    blinded = reported_closed is True and real_line.breaker_closed is False
    return AttackResult(
        name="hmi_blind",
        attack_class=7,
        title="Manipulation of view / HMI blinding",
        target_detection_layer="L3 physics (breaker/flow consistency + plausibility)",
        executed=blinded,
        changed=[
            f"froze RTUs {freeze_rtus} — they now report stale nominal values",
            f"tripped line {divert_line} in the REAL grid behind the frozen view",
            f"operator still sees line {divert_line} breaker="
            f"{'CLOSED' if reported_closed else 'OPEN'} @ {reported_loading:.0f}% "
            f"loading; reality: breaker={'CLOSED' if real_line.breaker_closed else 'OPEN'}, "
            f"system max loading {real_max_loading:.0f}%",
        ],
        evidence={
            "frozen_rtus": freeze_rtus,
            "reported_breaker_closed": reported_closed,
            "real_breaker_closed": real_line.breaker_closed,
            "reported_loading_pct": reported_loading,
            "real_system_max_loading_pct": round(real_max_loading, 1),
            "real_tripped_lines": real_snap.tripped_lines(),
        },
        why_hard_to_catch=(
            "The frozen RTUs return perfectly valid, in-range Modbus responses — the "
            "values were real a moment ago and nothing about a single reading looks "
            "wrong, so protocol and range checks pass. There is no malicious *command* "
            "to flag either; only the process-view is corrupted. The contradiction is "
            "physical: a breaker reported CLOSED with nominal flow while neighbouring "
            "measurements imply that line is de-energised and the corridor is "
            "overloaded. Detecting that needs L3's breaker/flow consistency test and a "
            "plausibility check against the last known-good trusted state."
        ),
        artifacts={},
    )


def _extra(p):
    p.add_argument("--divert-line", type=int, default=26)


if __name__ == "__main__":
    raise SystemExit(cli_main(run, extra_args=_extra))
