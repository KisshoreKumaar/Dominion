"""SCADA system orchestration — grid + RTU farm + control center in one object.

This is the handle later phases attach to: the attack scripts talk to the RTU
ports, the detection layers read the capture bus, and containment drives the
control center / engine. Bringing it up here keeps that wiring in one place.
"""
from __future__ import annotations

import time
from typing import Optional

from grid.engine import GridEngine
from .capture import CaptureBus, get_capture
from .control_center import ControlCenter
from .rtu_server import RTUFarm


class ScadaSystem:
    def __init__(self, engine: Optional[GridEngine] = None,
                 capture: Optional[CaptureBus] = None, tick_hz: float = 1.0):
        self.engine = engine or GridEngine(tick_hz=tick_hz)
        self.capture = capture if capture is not None else get_capture()
        self.farm = RTUFarm(self.engine, self.capture)
        self.control = ControlCenter(self.farm.specs, self.capture)
        self._started = False

    def start(self, run_grid: bool = True) -> None:
        """Start grid loop, RTU servers, and connect the control center."""
        if run_grid:
            self.engine.start_background()
        self.farm.start()             # binds all RTU TCP ports
        time.sleep(0.4)               # let ports settle
        self.control.connect()        # open client sockets to every RTU
        self._started = True

    def stop(self) -> None:
        self.control.stop_polling()
        self.control.close()
        self.farm.stop()
        self.engine.stop()

    @property
    def specs(self):
        return self.farm.specs

    def endpoints(self) -> list[dict]:
        return self.farm.endpoints()
