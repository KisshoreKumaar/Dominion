"""L2 protocol detector — Modbus command policy over the capture bus.

Learns a baseline of *normal* SCADA protocol behaviour from Phase 2's legitimate
traffic, then flags protocol-level abuse. Four complementary checks, each
producing an explainable DetectionEvent:

  1. Function-code allowlist / write authorization — writes (FC 5/6/15/16) are
     only legitimate from a known master (the control center); a write from any
     other source, or an FC never seen for that RTU, is a violation. (Catches the
     replay #4 and setpoint #5 sessions, which originate from attacker hosts.)
  2. Replay signature — a write frame byte-identical to one a master already sent,
     now re-sent by a different source, is a replay. (Catches #4 precisely.)
  3. Write-rate ceiling — more than `max_writes_per_s` writes from one source in a
     1 s window is faster than any operator workflow. (Catches the #5 burst.)
  4. Command-sequence (Markov) model — a first-order model over the per-source
     function-code order; a transition never seen in the baseline is corroborating
     evidence that the command stream is not a normal operator workflow.

Everything is contextual/among-frames: each individual frame is valid Modbus, so
only a learned protocol baseline can see the abuse.
"""
from __future__ import annotations

from collections import defaultdict, deque

from ..events import DetectionEvent, STAGE_COMMAND

WRITE_FCS = {5, 6, 15, 16}


class ProtocolBaseline:
    def __init__(self):
        self.masters: set[str] = set()                       # sources that legitimately write
        self.fc_per_rtu: dict[str, set[int]] = defaultdict(set)
        self.bigrams: set[tuple[int, int]] = set()           # (prev_fc, fc) seen per source
        self.max_writes_per_s: float = 2.0                   # ceiling (raised by observed rate)
        self.n_learned = 0

    def learn(self, events) -> "ProtocolBaseline":
        last_fc: dict[str, int] = {}
        # measure legitimate burstiness to set a non-trivial but safe ceiling
        win: dict[str, deque] = defaultdict(deque)
        for e in sorted(events, key=lambda x: x.ts):
            if e.capture_point != "client":
                continue
            self.fc_per_rtu[e.dst].add(e.function_code)
            if e.src in last_fc:
                self.bigrams.add((last_fc[e.src], e.function_code))
            last_fc[e.src] = e.function_code
            if e.function_code in WRITE_FCS:
                self.masters.add(e.src)
                dq = win[e.src]
                dq.append(e.ts)
                while dq and e.ts - dq[0] > 1.0:
                    dq.popleft()
                self.max_writes_per_s = max(self.max_writes_per_s, float(len(dq)))
            self.n_learned += 1
        return self


class ProtocolDetector:
    def __init__(self, baseline: ProtocolBaseline, rate_ceiling: float | None = None):
        self.baseline = baseline
        # allow a little headroom above the fastest legitimate burst
        self.rate_ceiling = rate_ceiling if rate_ceiling is not None else max(3.0, baseline.max_writes_per_s + 1.0)

    def detect(self, events, emit_to=None) -> list[DetectionEvent]:
        out: list[DetectionEvent] = []
        master_frames: set[tuple] = set()      # frames legitimately sent by masters
        write_times: dict[str, deque] = defaultdict(deque)
        last_fc: dict[str, int] = {}
        emitted_keys: set[tuple] = set()

        def add(ev: DetectionEvent, dedup_key):
            if dedup_key in emitted_keys:
                return
            emitted_keys.add(dedup_key)
            out.append(ev)
            if emit_to is not None:
                emit_to.emit(ev)

        for e in sorted(events, key=lambda x: x.ts):
            if e.capture_point != "client":
                continue
            fc = e.function_code
            src, rtu = e.src, e.dst
            is_master = src in self.baseline.masters
            frame = (rtu, fc, e.address, tuple(e.values))

            # sequence bigram check (corroborating)
            if src in last_fc:
                bigram = (last_fc[src], fc)
                if bigram not in self.baseline.bigrams and not is_master:
                    add(DetectionEvent(
                        detector="L2.protocol.sequence", layer="L2", attack_stage=STAGE_COMMAND,
                        title=f"Anomalous command sequence from {src}",
                        reason=(f"function-code transition {last_fc[src]}->{fc} to {rtu} from "
                                f"'{src}' was never seen in the baseline command order."),
                        confidence=0.55, severity="low",
                        entities={"src_label": src, "dst_rtu": rtu},
                        evidence={"transition": [last_fc[src], fc], "src": src, "dst": rtu},
                        ts=e.ts), ("seq", src, rtu))
            last_fc[src] = fc

            if fc in WRITE_FCS:
                # --- write-rate ceiling ---
                dq = write_times[src]
                dq.append(e.ts)
                while dq and e.ts - dq[0] > 1.0:
                    dq.popleft()
                rate = len(dq)
                if rate > self.rate_ceiling:
                    add(DetectionEvent(
                        detector="L2.protocol.write_rate", layer="L2", attack_stage=STAGE_COMMAND,
                        title=f"Write-rate ceiling exceeded from {src}",
                        reason=(f"{rate} writes/s from '{src}' to {rtu} exceeds the ceiling of "
                                f"{self.rate_ceiling:.0f}/s (legitimate operator ramps are < 1/s)."),
                        confidence=0.85, severity="high",
                        entities={"src_label": src, "dst_rtu": rtu},
                        evidence={"writes_per_s": rate, "ceiling": self.rate_ceiling,
                                  "function_code": fc, "src": src, "dst": rtu},
                        ts=e.ts), ("rate", src, rtu))

                if not is_master:
                    # --- replay signature (matches a frame a master already sent) ---
                    if frame in master_frames:
                        add(DetectionEvent(
                            detector="L2.protocol.replay", layer="L2", attack_stage=STAGE_COMMAND,
                            title=f"Replayed command from {src}",
                            reason=(f"write frame FC{fc} addr={e.address} val={e.values} to {rtu} is "
                                    f"byte-identical to a command a master already issued, now re-sent "
                                    f"by non-master '{src}' — a replay."),
                            confidence=0.9, severity="high",
                            entities={"src_label": src, "dst_rtu": rtu},
                            evidence={"function_code": fc, "address": e.address, "values": e.values,
                                      "src": src, "dst": rtu, "replayed": True},
                            ts=e.ts), ("replay", src, rtu, frame))
                    # --- write authorization (writes only from a known master) ---
                    add(DetectionEvent(
                        detector="L2.protocol.allowlist", layer="L2", attack_stage=STAGE_COMMAND,
                        title=f"Unauthorized write from {src}",
                        reason=(f"write FC{fc} to {rtu} from '{src}' ({e.src_host}), which is not a "
                                f"known control master {sorted(self.baseline.masters)}; writes are "
                                f"only authorised from the control center."),
                        confidence=0.88, severity="high",
                        entities={"src_label": src, "host": e.src_host, "dst_rtu": rtu},
                        evidence={"function_code": fc, "src": src, "src_host": e.src_host,
                                  "dst": rtu, "known_masters": sorted(self.baseline.masters)},
                        ts=e.ts), ("authz", src, rtu))
                else:
                    # legitimate master write — always track the frame so any later
                    # non-master replay of it is caught, then check the FC allowlist
                    master_frames.add(frame)
                    if fc not in self.baseline.fc_per_rtu.get(rtu, set()):
                        add(DetectionEvent(
                            detector="L2.protocol.allowlist", layer="L2", attack_stage=STAGE_COMMAND,
                            title=f"Out-of-policy function code FC{fc} on {rtu}",
                            reason=(f"master '{src}' used FC{fc} on {rtu}, never seen for that RTU in "
                                    f"the baseline allowlist {sorted(self.baseline.fc_per_rtu.get(rtu, set()))}."),
                            confidence=0.6, severity="medium",
                            entities={"src_label": src, "dst_rtu": rtu},
                            evidence={"function_code": fc, "src": src, "dst": rtu},
                            ts=e.ts), ("fc", src, rtu, fc))

        return out
