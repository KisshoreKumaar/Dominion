"""GRIDSENTINEL API — live grid feed over HTTP + WebSocket.

Phase 1 scope: expose the running GridEngine's state so a frontend (Phase 7)
can render it, and so later phases have a place to hang SCADA, detection, and
response endpoints. Kept intentionally small here.

Run:
    python -m api.app            # serves on http://127.0.0.1:8000
    python scripts/run_demo.py --api

Endpoints:
    GET  /                 -> service info
    GET  /state            -> latest GridSnapshot as JSON
    GET  /topology         -> static bus/line/trafo layout (for the diagram)
    POST /control/trip/{line_id}   -> queue a manual breaker-open (demo aid)
    POST /control/close/{line_id}  -> queue a manual breaker-close
    WS   /ws               -> pushes every new GridSnapshot as JSON

The engine runs in a background thread; the WebSocket bridges its snapshot
callbacks onto each connected client via an asyncio queue.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from grid.engine import GridEngine

app = FastAPI(title="GRIDSENTINEL", version="0.1.0")

# Single shared engine + the set of connected websocket queues.
_engine: Optional[GridEngine] = None
_clients: set[asyncio.Queue] = set()
_loop: Optional[asyncio.AbstractEventLoop] = None


def get_engine() -> GridEngine:
    global _engine
    if _engine is None:
        _engine = GridEngine(tick_hz=1.0)
    return _engine


def _on_snapshot(snap) -> None:
    """Engine callback (runs in the engine thread). Hand the snapshot to each
    websocket client's queue via the API event loop, thread-safely."""
    if _loop is None:
        return
    payload = snap.to_dict()
    for q in list(_clients):
        _loop.call_soon_threadsafe(q.put_nowait, payload)


@app.on_event("startup")
async def _startup() -> None:
    global _loop
    _loop = asyncio.get_running_loop()
    eng = get_engine()
    eng.subscribe(_on_snapshot)
    eng.start_background()


@app.on_event("shutdown")
async def _shutdown() -> None:
    if _engine:
        _engine.stop()


@app.get("/")
async def root() -> dict:
    eng = get_engine()
    snap = eng.snapshot
    return {
        "service": "GRIDSENTINEL",
        "version": app.version,
        "grid_case": "IEEE 39-bus New England",
        "tick": snap.tick,
        "converged": snap.converged,
        "clients_connected": len(_clients),
        "note": "frequency_hz is a demo-grade proxy from slack-bus deviation",
    }


@app.get("/state")
async def state() -> JSONResponse:
    return JSONResponse(get_engine().snapshot.to_dict())


@app.get("/topology")
async def topology() -> dict:
    """Static-ish layout for the one-line diagram: buses + line/trafo endpoints."""
    snap = get_engine().snapshot
    return {
        "buses": [{"bus_id": b.bus_id, "name": b.name, "vn_kv": b.vn_kv} for b in snap.buses],
        "lines": [{"line_id": l.line_id, "from_bus": l.from_bus, "to_bus": l.to_bus} for l in snap.lines],
        "trafos": [{"trafo_id": t.trafo_id, "hv_bus": t.hv_bus, "lv_bus": t.lv_bus} for t in snap.trafos],
    }


@app.post("/control/trip/{line_id}")
async def control_trip(line_id: int) -> dict:
    get_engine().trip_line(line_id, reason="api manual trip")
    return {"ok": True, "queued": f"open breaker on line {line_id}"}


@app.post("/control/close/{line_id}")
async def control_close(line_id: int) -> dict:
    get_engine().close_line(line_id, reason="api manual close")
    return {"ok": True, "queued": f"close breaker on line {line_id}"}


@app.websocket("/ws")
async def ws(websocket: WebSocket) -> None:
    await websocket.accept()
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    _clients.add(q)
    # send the current snapshot immediately so a fresh client isn't blank
    with contextlib.suppress(Exception):
        await websocket.send_json(get_engine().snapshot.to_dict())
    try:
        while True:
            payload = await q.get()
            await websocket.send_json(payload)
    except WebSocketDisconnect:
        pass
    finally:
        _clients.discard(q)


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
