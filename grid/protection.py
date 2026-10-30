"""Overload protection for the grid simulation.

Models the one piece of automatic control that lets *cascades emerge* rather
than being scripted (Phase 1 requirement): each line and transformer has a
simple time-overcurrent style breaker. If an element stays above its rating
for ``pickup_ticks`` consecutive ticks, its breaker trips (element taken out
of service). The power flow on the next tick then redistributes flow onto the
remaining elements, which may push *those* over their ratings, and so on — a
cascade that arises from physics + this local logic, not from a script.

This module is deliberately dumb and self-contained: it holds only per-element
overload counters and decides trips. It does not run power flow itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class OverloadProtection:
    # An element must exceed threshold for this many consecutive ticks to trip.
    pickup_ticks: int = 3
    # Trip when loading exceeds this percent of rating.
    threshold_percent: float = 100.0
    # Per-element consecutive-overload counters, keyed by ("line", idx) etc.
    _counters: dict[tuple[str, int], int] = field(default_factory=dict)
    # Elements already tripped by protection (so we don't re-count them).
    _tripped: set[tuple[str, int]] = field(default_factory=set)

    def reset(self) -> None:
        self._counters.clear()
        self._tripped.clear()

    def note_external_trip(self, kind: str, idx: int) -> None:
        """Record a trip caused from outside protection (manual/attack) so the
        counters stay consistent and we don't try to re-trip it."""
        self._tripped.add((kind, idx))
        self._counters.pop((kind, idx), None)

    def clear_element(self, kind: str, idx: int) -> None:
        """Element was re-energised (breaker reclosed) — forget its history."""
        self._tripped.discard((kind, idx))
        self._counters.pop((kind, idx), None)

    def evaluate(self, loadings: dict[tuple[str, int], float]) -> list[tuple[str, int, float, int]]:
        """Given this tick's loading percents, advance counters and return trips.

        ``loadings`` maps (kind, idx) -> loading_percent for every in-service,
        breaker-controlled element.

        Returns a list of (kind, idx, loading_percent, ticks_over) for elements
        that should trip on THIS tick. The caller is responsible for actually
        opening the breaker; this keeps protection side-effect free and easy to
        unit test.
        """
        trips: list[tuple[str, int, float, int]] = []
        for key, loading in loadings.items():
            if key in self._tripped:
                continue
            if loading > self.threshold_percent:
                self._counters[key] = self._counters.get(key, 0) + 1
                if self._counters[key] >= self.pickup_ticks:
                    kind, idx = key
                    trips.append((kind, idx, loading, self._counters[key]))
                    self._tripped.add(key)
                    self._counters.pop(key, None)
            else:
                # Reset the counter the moment loading returns below threshold.
                self._counters.pop(key, None)
        return trips

    def counters_snapshot(self) -> dict[str, int]:
        """Human-readable view of currently-elevated counters (for debugging)."""
        return {f"{k[0]}:{k[1]}": v for k, v in self._counters.items() if v > 0}
