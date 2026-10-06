"""
ITAP — WebSocket Connection Manager
Manages real-time broadcast connections for live threat feed.
"""
import json
import logging
import asyncio
from datetime import datetime
from typing import List, Dict, Any
from fastapi import WebSocket

from app.core.security import decode_token, is_token_revoked

logger = logging.getLogger("itap.websocket")

# A client must present a valid token this many seconds after connecting.
WS_AUTH_TIMEOUT = 10


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts events.

    A freshly accepted socket is *pending*: it is held in a separate bucket and
    receives nothing until it authenticates. Previously the endpoint accepted and
    immediately broadcast every threat_detected, incident_created, scan_complete and
    system_event — including target domains, blocked IPs and operator usernames — to
    anyone who could open the socket, with no token at all.
    """

    # Unbounded sockets are a trivial memory-exhaustion lever.
    MAX_CONNECTIONS = 50

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._pending: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> bool:
        """Accept the socket into the pending bucket. Returns False if rejected."""
        await websocket.accept()
        if len(self.active_connections) + len(self._pending) >= self.MAX_CONNECTIONS:
            logger.warning("WebSocket rejected: connection cap reached")
            await websocket.close(code=1013)  # 1013 = try again later
            return False
        self._pending.append(websocket)
        logger.info(
            f"WebSocket pending authentication. Active: {len(self.active_connections)}, "
            f"pending: {len(self._pending)}"
        )
        return True

    def promote(self, websocket: WebSocket) -> bool:
        """Move an authenticated socket into the broadcast set."""
        if websocket not in self._pending:
            return False
        self._pending.remove(websocket)
        self.active_connections.append(websocket)
        logger.info(f"WebSocket authenticated. Active: {len(self.active_connections)}")
        return True

    async def authenticate(self, websocket: WebSocket) -> bool:
        """Read the first frame as ``{"type": "auth", "token": "<jwt>"}``.

        Browser WebSocket clients cannot set an Authorization header, so the token
        arrives as a handshake frame. Any failure closes the socket with 4401 and
        leaves it unsubscribed.
        """
        try:
            raw = await asyncio.wait_for(websocket.receive_text(), timeout=WS_AUTH_TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning("WebSocket closed: no auth frame within %ss", WS_AUTH_TIMEOUT)
            await websocket.close(code=4401)
            self.disconnect(websocket)
            return False
        except Exception:
            self.disconnect(websocket)
            return False

        try:
            message = json.loads(raw)
        except (ValueError, TypeError):
            message = {"type": "auth", "token": raw.strip()} if raw.strip() else {}

        token = (message or {}).get("token")
        if (message or {}).get("type") != "auth" or not token:
            logger.warning("WebSocket rejected: first frame was not an auth handshake")
            await websocket.close(code=4401)
            self.disconnect(websocket)
            return False

        try:
            payload = decode_token(token)
            if payload.get("type") != "access" or not payload.get("jti"):
                raise ValueError("not an access token with a revocable id")
            if is_token_revoked(payload):
                raise ValueError("token revoked")
        except Exception as exc:
            logger.warning(f"WebSocket rejected: invalid token ({exc})")
            await websocket.close(code=4401)
            self.disconnect(websocket)
            return False

        self.promote(websocket)
        await self.send_personal_message({
            "type": "connected",
            "message": "ITAP Live Feed connected",
            "user": payload.get("sub"),
            "role": payload.get("role"),
            "timestamp": datetime.utcnow().isoformat(),
            "active_connections": len(self.active_connections),
        }, websocket)
        return True

    def disconnect(self, websocket: WebSocket):
        for bucket in (self.active_connections, self._pending):
            if websocket in bucket:
                bucket.remove(websocket)
        logger.info(
            f"WebSocket disconnected. Active: {len(self.active_connections)}, "
            f"pending: {len(self._pending)}"
        )

    async def send_personal_message(self, data: Dict[str, Any], websocket: WebSocket):
        try:
            await websocket.send_text(json.dumps(data))
        except Exception:
            self.disconnect(websocket)

    async def broadcast(self, data: Dict[str, Any]):
        """Broadcast a message to every authenticated client.

        Sends concurrently and tolerates individual failures, so one dead socket
        cannot stall the broadcaster (previously a loop of sequential awaits).
        """
        if not self.active_connections:
            return
        message = json.dumps(data)
        results = await asyncio.gather(
            *(conn.send_text(message) for conn in list(self.active_connections)),
            return_exceptions=True,
        )
        for conn, result in zip(list(self.active_connections), results):
            if isinstance(result, Exception):
                self.disconnect(conn)

    async def broadcast_threat(self, threat_data: Dict[str, Any]):
        """Broadcast a new threat detection event."""
        await self.broadcast({
            "type": "threat_detected",
            "data": threat_data,
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def broadcast_scan_complete(self, scan_data: Dict[str, Any]):
        """Broadcast scan completion event."""
        await self.broadcast({
            "type": "scan_complete",
            "data": scan_data,
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def broadcast_incident(self, incident_data: Dict[str, Any]):
        """Broadcast a new incident creation."""
        await self.broadcast({
            "type": "incident_created",
            "data": incident_data,
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def broadcast_system_event(self, level: str, message: str, detail: str = ""):
        """Broadcast a system log event."""
        await self.broadcast({
            "type": "system_event",
            "level": level,       # info | warning | error | critical
            "message": message,
            "detail": detail,
            "timestamp": datetime.utcnow().isoformat(),
        })


# Global singleton
manager = ConnectionManager()
