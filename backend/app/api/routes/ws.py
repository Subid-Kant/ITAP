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

logger = logging.getLogger("itap.websocket")


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts events."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Active: {len(self.active_connections)}")
        # Send welcome message
        await self.send_personal_message({
            "type": "connected",
            "message": "ITAP Live Feed connected",
            "timestamp": datetime.utcnow().isoformat(),
            "active_connections": len(self.active_connections),
        }, websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Active: {len(self.active_connections)}")

    async def send_personal_message(self, data: Dict[str, Any], websocket: WebSocket):
        try:
            await websocket.send_text(json.dumps(data))
        except Exception:
            self.disconnect(websocket)

    async def broadcast(self, data: Dict[str, Any]):
        """Broadcast a message to all connected clients."""
        if not self.active_connections:
            return
        message = json.dumps(data)
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                dead_connections.append(connection)
        for conn in dead_connections:
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
