"""
WebSocket Connection Manager for live Boundary Updates, Drift Detections,
Agent Health, Query Progress and Case Updates.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self.active.append(ws)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            if ws in self.active:
                self.active.remove(ws)

    async def broadcast(self, event_type: str, payload: Dict[str, Any]):
        message = json.dumps({"type": event_type, "payload": payload}, default=str)
        stale = []
        for ws in list(self.active):
            try:
                await ws.send_text(message)
            except Exception:
                stale.append(ws)
        for ws in stale:
            await self.disconnect(ws)


manager = ConnectionManager()
