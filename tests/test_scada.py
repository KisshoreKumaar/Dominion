"""Phase 2 DoD tests for the SCADA layer.

Uses one module-scoped ScadaSystem (real Modbus/TCP servers on real ports) to
avoid rebinding ports per test.
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scada.scada_system import ScadaSystem
from scada.capture import CaptureBus
from scada import rtu_map as rm


@pytest.fixture(scope="module")
def scada():
    cap = CaptureBus()
    sysm = ScadaSystem(capture=cap, tick_hz=8.0)
    sysm.start()
    time.sleep(1.0)
    yield sysm, cap
    sysm.stop()
    time.sleep(0.3)


def test_rtus_online_and_poll_matches_grid(scada):
    sysm, cap = scada
    # poll an RTU on the cascade corridor and compare to the grid snapshot
    d = sysm.control.poll_rtu("rtu-21")
    snap = sysm.engine.snapshot
    bus = next(b for b in snap.buses if b.bus_id == 21)
    assert abs(d["vm_pu"] - bus.vm_pu) < 0.01, "polled voltage must match grid"
    assert abs(d["freq_hz"] - snap.frequency_hz) < 0.01
    # a monitored line's flow should match (within encoding resolution of 1 MW)
    line26 = next(l for l in snap.lines if l.line_id == 26)
    polled26 = next(l for l in d["lines"] if l["line_id"] == 26)
    assert abs(polled26["p_mw"] - line26.p_from_mw) <= 1.5


def test_legit_breaker_command_changes_grid(scada):
    sysm, cap = scada
    eng = sysm.engine
    # ensure line 20 breaker is closed to start (rtu-15 monitors it)
    line_id = 20
    if not next(l.breaker_closed for l in eng.snapshot.lines if l.line_id == line_id):
        sysm.control.operate_breaker("rtu-15", line_id, close=True)
        time.sleep(0.6)
    assert next(l.breaker_closed for l in eng.snapshot.lines if l.line_id == line_id)

    # FC5 legitimate OPEN command
    sysm.control.operate_breaker("rtu-15", line_id, close=False)
    # wait for the engine to apply it on a subsequent tick
    deadline = time.time() + 3.0
    opened = False
    while time.time() < deadline:
        if not next(l.breaker_closed for l in eng.snapshot.lines if l.line_id == line_id):
            opened = True
            break
        time.sleep(0.05)
    assert opened, "legitimate breaker command must change grid state"

    # restore for other tests
    sysm.control.operate_breaker("rtu-15", line_id, close=True)
    time.sleep(0.6)


def test_all_required_function_codes_on_the_wire(scada):
    sysm, cap = scada
    cap.clear()
    # poll (FC3, FC4, FC2) + all four write codes
    sysm.control.poll_rtu("rtu-21")
    sysm.control.operate_breaker("rtu-21", 27, close=True)                 # FC5
    sysm.control.set_generator_setpoint("rtu-32", 500.0)                   # FC6
    sysm.control.operate_breakers_multi("rtu-21", [True, True])            # FC15
    sysm.control.set_setpoints_multi("rtu-32", [rm.enc_mw(500.0)])         # FC16
    time.sleep(0.3)
    server_fcs = set(e.function_code for e in cap.events(capture_point="rtu"))
    assert {3, 4, 5, 6, 15, 16}.issubset(server_fcs), f"missing FCs, saw {sorted(server_fcs)}"


def test_capture_event_has_l2_fields(scada):
    sysm, cap = scada
    cap.clear()
    sysm.control.operate_breaker("rtu-21", 26, close=True, )  # a write with a decode note
    time.sleep(0.2)
    client_events = cap.events(capture_point="client")
    assert client_events, "client-side capture must record the command"
    e = client_events[-1]
    # every field L1/L2 need must be present and populated
    assert e.src and e.dst
    assert e.src_port >= 0 and e.dst_port > 0
    assert e.function_code == 5
    assert e.fc_name == "write_coil"
    assert e.address is not None
    assert isinstance(e.values, list) and len(e.values) >= 1
    assert e.ts > 0 and e.ts_iso


def test_write_reaches_correct_grid_element_via_bridge(scada):
    sysm, cap = scada
    # FC6 setpoint on rtu-32 should change generator 2's setpoint in the model
    eng = sysm.engine
    sysm.control.set_generator_setpoint("rtu-32", 470.0)
    time.sleep(0.6)
    assert abs(float(eng.net.gen.at[2, "p_mw"]) - 470.0) < 1.0


def test_capture_fail_open_on_bad_subscriber(scada):
    sysm, cap = scada

    def boom(_e):
        raise RuntimeError("bad detector")

    cap.subscribe(boom)
    # a poll must still succeed despite a raising subscriber
    d = sysm.control.poll_rtu("rtu-15")
    assert d["rtu_id"] == "rtu-15"
