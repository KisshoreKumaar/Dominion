"""Attack #3 — Unauthorized boundary traversal.

Opens a Modbus/TCP session to an RTU from a host/port + identity the SCADA
baseline has never seen, at an off-hours timestamp. This is the attacker
pivoting from the compromised workstation across the IT/OT boundary and
touching a real RTU for the first time.

The session itself is the anomaly: a new (source, RTU, protocol) tuple at
03:xx, when the legitimate control center is the only thing that ever talks
Modbus to these RTUs, and only during operating hours.

Target detection layer: L1 (boundary) — first-seen host-pair + off-hours
session flags over the capture bus.
"""
from __future__ import annotations

from .common import AttackResult, register, cli_main, live_scada, off_hours_timestamp


ATTACKER_LABEL = "compromised-eng-laptop"
ATTACKER_HOST = "10.0.7.66"       # a corporate-subnet host, never a SCADA master


@register("boundary", attack_class=3, title="Unauthorized boundary traversal", layer="L1 boundary")
def run(rtu_id: str = "rtu-21", system=None) -> AttackResult:
    from scada.control_center import CapturingModbusClient

    with live_scada(system) as sysm:
        spec = next(s for s in sysm.specs if s.rtu_id == rtu_id)
        off_ts = off_hours_timestamp()

        # a brand-new Modbus client from an unfamiliar corporate host/identity
        atk = CapturingModbusClient(spec, src_label=ATTACKER_LABEL,
                                    capture=sysm.capture, src_host=ATTACKER_HOST)
        atk.ts_override = off_ts       # land at 03:17, an implausible operator time
        connected = atk.connect()

        # probe the RTU: enumerate registers (recon) — real Modbus reads on the wire
        atk.read_holding_registers(0, 3)     # FC3 setpoints
        atk.read_input_registers(0, 26)      # FC4 analog
        atk.read_discrete_inputs(0, 2)       # FC2 breaker status
        atk.close()

    return AttackResult(
        name="boundary",
        attack_class=3,
        title="Unauthorized boundary traversal (novel Modbus session)",
        target_detection_layer="L1 boundary (first-seen host-pair / off-hours)",
        executed=connected,
        changed=[
            f"opened a Modbus/TCP session to {rtu_id} from {ATTACKER_LABEL} "
            f"({ATTACKER_HOST}) — a source the baseline has never seen",
            "session timestamped at 03:17 (off-hours), outside operator activity",
            "enumerated the RTU register map with FC3/FC4/FC2 reads (recon)",
            "read-only so far — no writes, nothing physically changed yet",
        ],
        evidence={
            "src_label": ATTACKER_LABEL,
            "src_host": ATTACKER_HOST,
            "dst_rtu": rtu_id,
            "session_hour": 3,
            "known_masters": ["control-center"],
        },
        why_hard_to_catch=(
            "Nothing here is malformed and no value is out of range — these are "
            "perfectly valid Modbus reads that any protocol parser accepts. The only "
            "signal is contextual: this (source host -> RTU) pair has never appeared "
            "in the baseline, and it is happening at 03:17. A physics or protocol-"
            "content check sees nothing wrong; you need L1's learned baseline of who "
            "talks to whom and when to flag the new host-pair and the off-hours session."
        ),
        artifacts={},
    )


def _extra(p):
    p.add_argument("--rtu-id", default="rtu-21")


if __name__ == "__main__":
    raise SystemExit(cli_main(run, extra_args=_extra))
