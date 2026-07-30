"""
ITAP — Real-Time Server Monitoring Service
Monitors the local server (CPU, memory, disk, network connections)
using psutil. Auto-generates incidents when thresholds are exceeded.
"""
import asyncio
import psutil
import socket
import logging
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.database import async_session_factory
from app.models.models import Incident, SeverityLevel, IncidentStatus

logger = logging.getLogger("itap.monitor.server")

class ServerMonitor:
    def __init__(self):
        self.is_running = False
        self.cpu_threshold = 80.0
        self.memory_threshold = 80.0
        self.disk_threshold = 85.0
        self.last_alerts = {}  # Prevent alert spam
        self.startup_logged = False

    async def start(self):
        self.is_running = True
        logger.info("Started real-time server monitoring (psutil)")
        asyncio.create_task(self._monitor_loop())

    async def stop(self):
        self.is_running = False
        logger.info("Stopped server monitoring")

    async def get_current_stats(self) -> dict:
        """Get instant snapshot of server stats for the dashboard."""
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Get active network connections
        conns = []
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.status == 'ESTABLISHED':
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                    conns.append({"local": laddr, "remote": raddr, "pid": c.pid})
        except psutil.AccessDenied:
            pass # Requires admin on Windows for all connections
            
        return {
            "cpu_percent": cpu,
            "memory_percent": mem.percent,
            "memory_used_gb": round(mem.used / (1024**3), 2),
            "memory_total_gb": round(mem.total / (1024**3), 2),
            "disk_percent": disk.percent,
            "active_connections": len(conns),
            "connections_sample": conns[:10],
            "hostname": socket.gethostname(),
            "timestamp": datetime.utcnow().isoformat()
        }

    async def _monitor_loop(self):
        while self.is_running:
            try:
                stats = await self.get_current_stats()
                
                # Log a startup system event on first loop (disabled to prevent clutter)
                if not self.startup_logged:
                    self.startup_logged = True
                    
                await self._evaluate_thresholds(stats)
            except Exception as e:
                logger.error(f"Error in server monitor loop: {e}")
            await asyncio.sleep(15) # Check every 15 seconds

    async def _evaluate_thresholds(self, stats: dict):
        alerts = []
        
        if stats["cpu_percent"] > self.cpu_threshold:
            alerts.append({
                "type": "CPU_SPIKE",
                "title": f"Critical CPU Spike ({stats['cpu_percent']}%)",
                "severity": SeverityLevel.HIGH,
                "desc": f"Server CPU utilization has remained above {self.cpu_threshold}% threshold."
            })
            
        if stats["memory_percent"] > self.memory_threshold:
            alerts.append({
                "type": "MEMORY_EXHAUSTION",
                "title": f"Memory Exhaustion Warning ({stats['memory_percent']}%)",
                "severity": SeverityLevel.HIGH,
                "desc": f"Server memory utilization is critically high ({stats['memory_used_gb']}GB used)."
            })
            
        if stats["disk_percent"] > self.disk_threshold:
            alerts.append({
                "type": "DISK_WARNING",
                "title": f"Low Disk Space ({stats['disk_percent']}%)",
                "severity": SeverityLevel.MEDIUM,
                "desc": f"Server primary disk is nearing capacity."
            })
            
        # Check active connections for anomalous spikes (e.g. DoS or mass exfil)
        if stats["active_connections"] > 500: # Threshold for anomaly
             alerts.append({
                "type": "NETWORK_ANOMALY",
                "title": f"Unusual Network Connection Spike ({stats['active_connections']} active)",
                "severity": SeverityLevel.CRITICAL,
                "desc": f"Detected an abnormally high number of established network connections. Possible DoS or scanner activity."
            })

        for alert in alerts:
            # Simple debounce to prevent DB spam (alert once per hour per type)
            now = datetime.utcnow()
            last_time = self.last_alerts.get(alert["type"])
            if not last_time or (now - last_time).total_seconds() > 3600:
                self.last_alerts[alert["type"]] = now
                await self._create_incident(alert)

    async def _create_incident(self, alert: dict):
        try:
            async with async_session_factory() as db:
                incident = Incident(
                    title=f"[Local Server] {alert['title']}",
                    description=alert["desc"],
                    severity=alert["severity"],
                    status=IncidentStatus.OPEN,
                    source="server_monitor"  # Added source field
                )
                db.add(incident)
                await db.commit()
                logger.warning(f"Server Monitor triggered incident: {alert['title']}")
                
                # In a full implementation, we would broadcast a WebSocket event here
        except Exception as e:
            logger.error(f"Failed to create monitor incident: {e}")

server_monitor = ServerMonitor()
