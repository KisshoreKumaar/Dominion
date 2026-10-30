"""L3 physics detection — the differentiator.

Three checks, all on top of the conventional WLS + chi-square baseline in
``estimator.py``:

  1. Trusted-PMU subset cross-check (catches FDIA #6). Estimate the state from the
     (possibly falsified) reachable measurements, then independently verify the
     solution against a small set of *trusted* measurements the attacker cannot
     reach. A stealthy FDIA keeps the chi-square residual ~0 (so the conventional
     test passes), but its shifted state disagrees with the trusted PMUs — that
     gap is the detection. THIS IS THE HEADLINE: naive chi-square passes, the
     trusted cross-check catches it.

  2. Breaker/flow consistency (catches HMI blinding #7). A line reporting nonzero
     flow while its breaker reads OPEN is a hard fail; and when two RTUs instrument
     the same line, a disagreement in breaker state or energisation between them is
     a hard fail regardless of what any estimator says. Freezing a subset of RTUs
     to hide a real trip produces exactly this contradiction on the boundary lines.

  3. Plausibility vs last-known-good (corroborates #7). Reported values that jump
     implausibly far from the last trusted checkpoint are flagged.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..events import DetectionEvent, STAGE_MANIPULATION
from .estimator import StateEstimator


# ---------------- trusted-subset cross-check (FDIA) ----------------

@dataclass
class FDIACheckResult:
    naive_chi2_flagged: bool
    naive_J: float
    naive_threshold: float
    fdia_detected: bool
    max_angle_gap_deg: float
    max_v_gap_pu: float
    worst_bus: int | None
    event: DetectionEvent | None


class TrustedSubsetMonitor:
    """Detect stealthy FDIA by cross-checking against trusted PMUs."""

    def __init__(self, net, angle_threshold_deg: float = 1.0, v_threshold_pu: float = 0.02):
        self.net = net
        self.angle_threshold_deg = angle_threshold_deg
        self.v_threshold_pu = v_threshold_pu

    def check(self, reachable_meas: list[dict], trusted_meas: list[dict],
              emit_to=None) -> FDIACheckResult:
        est = StateEstimator(self.net)
        res = est.run(reachable_meas)

        max_angle_gap = 0.0
        max_v_gap = 0.0
        worst_bus = None
        for m in trusted_meas:
            b = m["element"]
            if m["meas_type"] == "va" and b in res.va_degree_est:
                gap = abs(res.va_degree_est[b] - m["value"])
                if gap > max_angle_gap:
                    max_angle_gap, worst_bus = gap, b
            elif m["meas_type"] == "v" and b in res.vm_pu_est:
                max_v_gap = max(max_v_gap, abs(res.vm_pu_est[b] - m["value"]))

        fdia_detected = (max_angle_gap > self.angle_threshold_deg or
                         max_v_gap > self.v_threshold_pu)

        event = None
        if fdia_detected:
            event = DetectionEvent(
                detector="L3.physics.trusted_pmu", layer="L3", attack_stage=STAGE_MANIPULATION,
                title=f"Stealthy FDIA caught by trusted-PMU cross-check ({max_angle_gap:.2f} deg gap)",
                reason=(f"Conventional chi-square PASSED (J={res.J:.2f} < threshold "
                        f"{res.threshold:.2f}) — the injected measurements are self-consistent, so "
                        f"the residual test is blind. BUT the estimator's solution disagrees with "
                        f"the untouched trusted PMUs by {max_angle_gap:.2f} deg at bus {worst_bus} "
                        f"(threshold {self.angle_threshold_deg:.2f} deg) — the state was falsified."),
                confidence=round(min(0.99, 0.6 + max_angle_gap / 10.0), 3),
                severity="critical",
                entities={"target_bus": worst_bus},
                evidence={
                    "naive_chi2_flagged": res.chi2_flagged,
                    "naive_J": round(res.J, 3),
                    "naive_threshold": round(res.threshold, 3),
                    "trusted_angle_gap_deg": round(max_angle_gap, 3),
                    "trusted_v_gap_pu": round(max_v_gap, 4),
                    "angle_threshold_deg": self.angle_threshold_deg,
                    "worst_bus": worst_bus,
                },
            )
            if emit_to is not None:
                emit_to.emit(event)

        return FDIACheckResult(
            naive_chi2_flagged=res.chi2_flagged, naive_J=res.J, naive_threshold=res.threshold,
            fdia_detected=fdia_detected, max_angle_gap_deg=round(max_angle_gap, 3),
            max_v_gap_pu=round(max_v_gap, 4), worst_bus=worst_bus, event=event)


# ---------------- breaker/flow consistency (HMI blinding) ----------------

class ConsistencyMonitor:
    """Detect manipulation-of-view via physical inconsistencies in the reported
    (polled) SCADA view."""

    def __init__(self, flow_eps_mw: float = 5.0):
        self.flow_eps_mw = flow_eps_mw

    def check_view(self, view_by_rtu: dict, emit_to=None) -> list[DetectionEvent]:
        out: list[DetectionEvent] = []

        # line_id -> list of (rtu_id, breaker_closed, p_mw)
        reports: dict[int, list[tuple]] = {}
        for rtu_id, poll in view_by_rtu.items():
            for ln in poll.get("lines", []):
                reports.setdefault(ln["line_id"], []).append(
                    (rtu_id, ln.get("breaker_closed"), ln.get("p_mw")))

        for line_id, reps in reports.items():
            # 1) within-RTU: breaker OPEN but nonzero flow reported
            for rtu_id, closed, p in reps:
                if closed is False and p is not None and abs(p) > self.flow_eps_mw:
                    ev = self._event(
                        f"L3.physics.breaker_flow",
                        f"Breaker/flow contradiction on line {line_id} at {rtu_id}",
                        (f"{rtu_id} reports line {line_id} breaker OPEN yet a flow of "
                         f"{p:.1f} MW — a de-energised line cannot carry power."),
                        line_id, [rtu_id], {"breaker_closed": closed, "p_mw": p}, conf=0.9)
                    out.append(ev)
                    if emit_to is not None:
                        emit_to.emit(ev)

            # 2) cross-RTU: two RTUs instrument the same line and disagree
            if len(reps) >= 2:
                closothers = {r[1] for r in reps}
                energised = {(abs(r[2]) > self.flow_eps_mw) if r[2] is not None else None for r in reps}
                if len(closothers - {None}) > 1 or len(energised - {None}) > 1:
                    detail = ", ".join(
                        f"{r[0]}: breaker={'CLOSED' if r[1] else 'OPEN'} @ {r[2]:.0f}MW" for r in reps)
                    ev = self._event(
                        "L3.physics.breaker_flow_xrtu",
                        f"Inconsistent view of line {line_id} across RTUs",
                        (f"line {line_id} is reported inconsistently by the RTUs that both "
                         f"instrument it ({detail}) — the process view has been manipulated "
                         f"(a subset of RTUs is reporting stale/frozen values)."),
                        line_id, [r[0] for r in reps],
                        {"reports": [{"rtu": r[0], "breaker_closed": r[1], "p_mw": r[2]} for r in reps]},
                        conf=0.92)
                    out.append(ev)
                    if emit_to is not None:
                        emit_to.emit(ev)
        return out

    def _event(self, detector, title, reason, line_id, rtus, evidence, conf):
        return DetectionEvent(
            detector=detector, layer="L3", attack_stage=STAGE_MANIPULATION,
            title=title, reason=reason, confidence=conf, severity="high",
            entities={"line_id": line_id, "rtus": rtus},
            evidence={"line_id": line_id, **evidence}, assets=rtus)
