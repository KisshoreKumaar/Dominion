"""Attack harness — imports every attack so the registry is populated, and
offers a single entry point to run one or all of them by name.

Used by scripts/run_demo.py (--attack / --list-attacks) and by Phase 8 metrics.
"""
from __future__ import annotations

# importing each module runs its @register decorator
from . import phishing, malware, boundary, replay, setpoint, fdia, hmi_blind  # noqa: F401
from .common import registry, get_attack, AttackResult

# canonical order = attack class number
ATTACK_ORDER = ["phishing", "malware", "boundary", "replay", "setpoint", "fdia", "hmi_blind"]


def list_attacks() -> list[dict]:
    reg = registry()
    out = []
    for name in ATTACK_ORDER:
        if name in reg:
            out.append({"name": name, "class": reg[name]["attack_class"],
                        "title": reg[name]["title"], "layer": reg[name]["layer"]})
    return out


def run_attack(name: str, **kwargs) -> AttackResult:
    entry = get_attack(name)
    if entry is None:
        raise KeyError(f"unknown attack '{name}'. Known: {ATTACK_ORDER}")
    return entry["run"](**kwargs)
