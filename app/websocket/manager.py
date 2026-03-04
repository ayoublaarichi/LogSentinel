"""
WebSocket connection manager — per-user event broadcasting.

Each authenticated user has their own set of WebSocket connections.
When new events are ingested, only that user's connections receive
the broadcast.  Other users' events are never leaked.

Authentication:  The WebSocket handshake reads the session cookie
the same way page routes do.  If no valid session is found, the
connection is rejected (code 4001).
"""

import asyncio
import json
from datetime import datetime
from typing import Optional

from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

# user_id → set of WebSocket connections
_connections: dict[int, set[WebSocket]] = {}


async def connect(ws: WebSocket, user_id: int) -> None:
    await ws.accept()
    _connections.setdefault(user_id, set()).add(ws)


def disconnect(ws: WebSocket, user_id: int) -> None:
    if user_id in _connections:
        _connections[user_id].discard(ws)
        if not _connections[user_id]:
            del _connections[user_id]


def broadcast_events(user_id: int, events: list) -> None:
    """
    Broadcast new events to all connected WebSocket clients of this user.
    Called from synchronous code (ingest/upload router) — schedules the
    async send on the running event loop if one exists.
    """
    conns = _connections.get(user_id, set())
    if not conns:
        return

    payload = json.dumps([
        {
            "id": getattr(e, "id", 0),
            "timestamp": e.timestamp.isoformat() if isinstance(e.timestamp, datetime) else str(e.timestamp),
            "source_ip": e.source_ip,
            "username": e.username,
            "event_type": e.event_type,
            "log_source": e.log_source,
            "raw_line": e.raw_line[:300],
        }
        for e in events
    ])

    try:
        loop = asyncio.get_running_loop()
        for ws in list(conns):
            loop.create_task(_safe_send(ws, user_id, payload))
    except RuntimeError:
        pass  # no event loop running — skip (e.g. during tests)


async def _safe_send(ws: WebSocket, user_id: int, text: str) -> None:
    try:
        if ws.client_state == WebSocketState.CONNECTED:
            await ws.send_text(text)
    except Exception:
        disconnect(ws, user_id)
