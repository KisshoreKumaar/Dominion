"""Shared scaffolding for the Phase 3 attack harness.

Every attack in GRIDSENTINEL is a self-contained module with a ``run(...)``
entry point and a CLI (``python -m attacks.<name>``). They attack ONLY our own
simulated grid and simulated RTUs (Section 1). Each ``run`` returns an
``AttackResult`` describing what it changed and — importantly — *why it is hard
to catch without the corresponding detection layer*, which is the story the
later detection phases have to deliver on.
"""
from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Callable, Optional


@dataclass
class AttackResult:
    name: str
    attack_class: int                 # 1..7 per the build plan
    title: str
    target_detection_layer: str       # which layer should catch it (L0/L1/L2/L3)
    executed: bool                    # did the attack actually run to completion
    changed: list[str] = field(default_factory=list)   # what it did, human-readable
    evidence: dict = field(default_factory=dict)       # structured facts for detection
    why_hard_to_catch: str = ""       # the naive-defense-evasion story
    artifacts: dict = field(default_factory=dict)      # data other phases consume

    def to_dict(self) -> dict:
        return asdict(self)

    def print_report(self) -> None:
        print("=" * 88)
        print(f"ATTACK #{self.attack_class}: {self.title}")
        print(f"  module: attacks.{self.name}   -> should be caught by: {self.target_detection_layer}")
        print("=" * 88)
        print("  what it changed:")
        for c in self.changed:
            print(f"    · {c}")
        if self.evidence:
            print("  evidence (for detection layers):")
            for k, v in self.evidence.items():
                vs = v if len(str(v)) < 100 else f"{str(v)[:97]}..."
                print(f"    - {k}: {vs}")
        print("  why it is hard to catch without the right layer:")
        for line in self.why_hard_to_catch.strip().splitlines():
            print(f"    {line.strip()}")
        print(f"  executed: {self.executed}")


# ---- attack registry (so Phase 8 metrics + the CLI can enumerate all 7) ----

_REGISTRY: dict[str, dict] = {}


def register(name: str, attack_class: int, title: str, layer: str):
    def deco(fn: Callable):
        _REGISTRY[name] = {"run": fn, "attack_class": attack_class,
                           "title": title, "layer": layer}
        return fn
    return deco


def registry() -> dict[str, dict]:
    return dict(_REGISTRY)


def get_attack(name: str) -> Optional[dict]:
    return _REGISTRY.get(name)


# ---- helpers ----

class live_scada:
    """Context manager that brings up a real SCADA system (grid + RTU farm +
    control center) for attacks that need live Modbus targets, and tears it
    down afterwards. Pass an existing ScadaSystem to attack that instead."""

    def __init__(self, system=None, tick_hz: float = 4.0, capture=None):
        self._own = system is None
        self._system = system
        self._tick_hz = tick_hz
        self._capture = capture

    def __enter__(self):
        if self._system is None:
            from scada.scada_system import ScadaSystem
            self._system = ScadaSystem(capture=self._capture, tick_hz=self._tick_hz)
            self._system.start()
            time.sleep(1.0)
        return self._system

    def __exit__(self, *exc):
        if self._own and self._system is not None:
            self._system.stop()
            time.sleep(0.3)
        return False


def off_hours_timestamp(hour: int = 3, minute: int = 17) -> float:
    """An epoch timestamp forced to the early hours — used to make attacks land
    at an implausible operator time that L1's hour-of-day baseline will flag."""
    now = datetime.now()
    ts = now.replace(hour=hour, minute=minute, second=4, microsecond=0)
    return ts.timestamp()


def cli_main(run: Callable[..., AttackResult], extra_args: Callable = None):
    """Standard CLI wrapper: runs the attack, prints its report, optional JSON."""
    p = argparse.ArgumentParser()
    p.add_argument("--json", action="store_true", help="emit the AttackResult as JSON")
    if extra_args:
        extra_args(p)
    args = p.parse_args()
    kwargs = {k: v for k, v in vars(args).items() if k != "json"}
    result = run(**kwargs)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
    else:
        result.print_report()
    return 0 if result.executed else 1
