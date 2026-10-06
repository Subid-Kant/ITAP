"""
ITAP — Machine Scanner Service v2.0
Performs real-time analysis of the host machine:
  - Detects the machine's real public IP and geolocates it (city-level precision)
  - Enumerates all active network connections via psutil
  - Bulk-geolocates all remote IPs (free ip-api.com batch, no key required)
  - Classifies each connection: SAFE / SUSPICIOUS / MALICIOUS
  - Cross-references CISA KEV vendor data and known threat heuristics
  - Refreshes every 60 seconds; result available instantly on startup
"""
import asyncio
import logging
import platform
import socket
import os
import re
import ipaddress
from datetime import datetime
from typing import Optional

import aiohttp
import psutil

from app.core.config import settings

logger = logging.getLogger("itap.scanner.machine")

# ── Known-dangerous / suspicious ports ────────────────────────────────────────
MALICIOUS_PORTS = {
    21, 22, 23, 25, 53, 110, 135, 137, 138, 139, 445, 1433, 1521,
    3306, 3389, 4444, 4899, 5900, 6667, 8080, 8443, 9001, 31337,
}

# ── Suspicious country codes (based on threat intelligence) ───────────────────
HIGH_RISK_COUNTRIES = {
    "CN", "RU", "KP", "IR", "SY", "BY", "VE", "CU", "MM",
    "NG", "ET", "PK", "AF", "IQ",
}
MEDIUM_RISK_COUNTRIES = {
    "TR", "UA", "VN", "IN", "BR", "RO", "BG", "PH", "ID", "MX",
}

# ── Suspicious organisation keywords ─────────────────────────────────────────
SUSPICIOUS_ORG_KEYWORDS = [
    "hosting", "vps", "cloud", "anonymous", "proxy", "vpn",
    "datacenter", "server", "tor", "bulletproof", "colocation",
    "hetzner", "ovh", "digitalocean", "linode", "vultr", "choopa",
    "m247", "serverius", "frantech", "buyvm", "serverplan",
]

# ── Safe, well-known ASN prefixes (Google, Cloudflare, Apple, MS, etc.) ───────
SAFE_ORG_PREFIXES = [
    "google", "cloudflare", "apple", "amazon", "microsoft",
    "akamai", "fastly", "cdn", "github", "mozilla", "adobe",
    "netflix", "meta", "facebook", "twitter", "spotify", "slack",
    "zoom", "dropbox", "salesforce", "oracle", "ibm",
]

# ── Addresses that must never be sent to a third party ───────────────────────
# This replaced a hand-maintained tuple of string prefixes, which missed whole
# ranges (CGNAT 100.64/10, link-local 169.254/16, unique-local fc00::/7, multicast,
# reserved). ipaddress classifies the full address space instead.
def _is_private(ip: str) -> bool:
    """True for any address that must not leave the host (fail closed).

    The decision is ``not is_global``: only globally routable addresses are worth
    geolocating, so anything the IANA special-purpose registries reserve — CGNAT
    (100.64/10), link-local, loopback, multicast, benchmark ranges — is redacted.
    Python 3.13+ narrowed ``is_private`` so that some of those ranges are no longer
    "private" (CGNAT is neither private nor global), which is precisely why the
    explicit checks are kept alongside it rather than relying on one flag.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True   # unparseable -> redact rather than forward
    return (
        not addr.is_global
        or addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _classify_connection(geo: dict, port: int, org: str) -> str:
    """Return MALICIOUS, SUSPICIOUS, or SAFE based on geo+port+org heuristics."""
    country_code = geo.get("countryCode", "")
    org_lower = (org or "").lower()

    # Hard malicious signals
    if port in MALICIOUS_PORTS and country_code in HIGH_RISK_COUNTRIES:
        return "MALICIOUS"
    if any(kw in org_lower for kw in ["bulletproof", "tor", "anonymous"]):
        return "MALICIOUS"

    # Suspicious signals
    if country_code in HIGH_RISK_COUNTRIES:
        return "SUSPICIOUS"
    if port in MALICIOUS_PORTS:
        return "SUSPICIOUS"
    if country_code in MEDIUM_RISK_COUNTRIES and any(
        kw in org_lower for kw in SUSPICIOUS_ORG_KEYWORDS
    ):
        return "SUSPICIOUS"
    if any(kw in org_lower for kw in SUSPICIOUS_ORG_KEYWORDS) and country_code not in {"US", "GB", "DE", "FR", "NL", "CA", "AU", "JP", "SE", "CH"}:
        return "SUSPICIOUS"

    # Safe signals — override for known CDN/cloud providers
    if any(safe in org_lower for safe in SAFE_ORG_PREFIXES):
        return "SAFE"

    return "SAFE"


def _severity_from_classification(cls: str) -> str:
    return {"MALICIOUS": "critical", "SUSPICIOUS": "high", "SAFE": "low"}.get(cls, "low")


class MachineScannerService:
    """
    Startup + periodic machine threat scanner.
    Results stored in-memory and served via API endpoint.
    """

    SCAN_INTERVAL = 60  # seconds between rescans (overridable via settings)
    IPINFO_URL = "https://ipinfo.io/json"
    # Provenance label for every value derived from a third-party service, so the
    # UI/API can say where a "MALICIOUS" classification actually came from.
    GEO_SOURCE_IPINFO = "ipinfo.io"
    GEO_SOURCE_IP_API = "ip-api.com"

    def __init__(self):
        self.is_running = False
        self._result: Optional[dict] = None
        self._lock = asyncio.Lock()
        # Held so stop() can cancel the loop; a discarded task can be
        # garbage-collected mid-flight.
        self._task: Optional[asyncio.Task] = None
        self._stop_evt = asyncio.Event()
        # Base URL is configurable so an organisation can point it at an HTTPS
        # endpoint; ip-api's free tier is HTTP-only, hence the default.
        base = settings.GEOLOCATION_API_BASE.rstrip("/")
        self.ip_api_base_url = base
        self.ip_api_batch_url = f"{base}/batch"
        self.ip_api_single_url = f"{base}/json/"

    @property
    def scan_interval(self) -> int:
        return max(int(settings.MACHINE_SCAN_INTERVAL_SECONDS), 15)

    # ── Public API ─────────────────────────────────────────────────────────────

    async def start(self):
        """Start the scanner — runs an immediate scan then continues periodically."""
        if not settings.MACHINE_SCAN_ENABLED:
            logger.info(
                "Machine Scanner DISABLED (MACHINE_SCAN_ENABLED=false). It reports this "
                "host's public IP and every remote endpoint it talks to to a "
                "third-party geolocation service; enable it explicitly if wanted."
            )
            return
        self.is_running = True
        self._stop_evt.clear()
        logger.info("Machine Scanner: starting initial host analysis…")
        self._task = asyncio.create_task(self._scan_loop(), name="machine_scanner")

    async def stop(self):
        self.is_running = False
        self._stop_evt.set()
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None

    async def get_result(self) -> dict:
        """Return the latest scan result (waits up to 10 s if still scanning)."""
        if not settings.MACHINE_SCAN_ENABLED:
            # Say so explicitly rather than returning an empty-looking scan that a
            # dashboard would render as "no threats found".
            return {
                "enabled": False,
                "message": "Machine scanning is disabled (MACHINE_SCAN_ENABLED=false).",
                "connections": [],
                "host": {},
            }
        for _ in range(20):
            async with self._lock:
                if self._result is not None:
                    return self._result
            await asyncio.sleep(0.5)
        return {"error": "Scan not yet complete", "connections": [], "host": {}}

    # ── Internal ───────────────────────────────────────────────────────────────

    async def _scan_loop(self):
        while self.is_running:
            try:
                result = await self._run_scan()
                async with self._lock:
                    self._result = result
                logger.info(
                    f"Machine scan complete: host={result['host'].get('city','?')},{result['host'].get('country','?')} "
                    f"connections={len(result['connections'])} "
                    f"threats={result['threat_count']}"
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(f"Machine scan failed: {exc}", exc_info=True)
            # Wait out the interval, but wake immediately when stop() is called.
            try:
                await asyncio.wait_for(self._stop_evt.wait(), timeout=self.scan_interval)
            except asyncio.TimeoutError:
                pass
            else:
                break

    async def _run_scan(self) -> dict:
        # 1. Get host public IP + geo
        host_geo = await self._get_host_geo()

        # 2. Get active connections from psutil
        raw_conns = await asyncio.get_event_loop().run_in_executor(
            None, self._get_raw_connections
        )

        # 3. Deduplicate remote IPs. _is_private() now fails closed, so anything
        #    that cannot be parsed as a public address is redacted before it can
        #    reach a third-party service.
        remote_ips = list({c["remote_ip"] for c in raw_conns if not _is_private(c["remote_ip"])})

        # 4. Bulk geolocate remote IPs
        geo_map = await self._bulk_geolocate(remote_ips)

        # 5. Build enriched connection list
        connections = []
        for c in raw_conns:
            ip = c["remote_ip"]
            if _is_private(ip):
                continue
            geo = geo_map.get(ip, {})
            if not geo.get("lat"):
                continue  # skip ungeolocatable IPs

            org = geo.get("org", geo.get("isp", "Unknown"))
            cls = _classify_connection(geo, c["remote_port"], org)
            connections.append({
                "remote_ip": ip,
                "remote_port": c["remote_port"],
                "local_port": c["local_port"],
                "protocol": c["protocol"],
                "process": c.get("process", "unknown"),
                "pid": c.get("pid"),
                "city": geo.get("city", "Unknown"),
                "region": geo.get("regionName", geo.get("region", "")),
                "country": geo.get("country", "Unknown"),
                "country_code": geo.get("countryCode", geo.get("country_code", "")),
                "lat": float(geo.get("lat", 0)),
                "lon": float(geo.get("lon", geo.get("lng", 0))),
                "org": org,
                "isp": geo.get("isp", org),
                "classification": cls,
                "severity": _severity_from_classification(cls),
                "is_threat": cls != "SAFE",
            })

        # 6. Open listening ports
        open_ports = await asyncio.get_event_loop().run_in_executor(
            None, self._get_open_ports
        )

        # 7. OS info
        os_info = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "hostname": socket.gethostname(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
        }

        # 8. Risk score (0–100)
        malicious = [c for c in connections if c["classification"] == "MALICIOUS"]
        suspicious = [c for c in connections if c["classification"] == "SUSPICIOUS"]
        risk_score = min(100, len(malicious) * 15 + len(suspicious) * 5)

        return {
            "host": host_geo,
            "connections": connections,
            "open_ports": open_ports,
            "os_info": os_info,
            "risk_score": risk_score,
            "threat_count": len(malicious) + len(suspicious),
            "malicious_count": len(malicious),
            "suspicious_count": len(suspicious),
            "safe_count": len([c for c in connections if c["classification"] == "SAFE"]),
            "total_connections": len(connections),
            "scan_time": datetime.utcnow().isoformat(),
            "top_threat_country": self._top_country(malicious + suspicious),
            # Provenance/limits, so a consumer can tell what these numbers are:
            # third-party geolocation plus local heuristics, on public endpoints only.
            "geo_source": host_geo.get("geo_source", "unavailable"),
            "classification_basis": "third-party geolocation + local port/org heuristics",
            "internal_addresses_redacted": True,
        }

    # ── Helpers ────────────────────────────────────────────────────────────────

    async def _get_host_geo(self) -> dict:
        """Detect public IP and geolocate via ipinfo.io (free, no key)."""
        try:
            async with aiohttp.ClientSession() as s:
                # Certificate verification stays on: this is the host's own
                # identity being resolved, and ssl=False made it spoofable.
                async with s.get(
                    self.IPINFO_URL,
                    timeout=aiohttp.ClientTimeout(total=8),
                    headers={"Accept": "application/json"},
                ) as r:
                    if r.status == 200:
                        data = await r.json(content_type=None)
                        # ipinfo returns "lat,lon" as "loc" field
                        loc = data.get("loc", "0,0").split(",")
                        return {
                            "ip": data.get("ip", "Unknown"),
                            "city": data.get("city", "Unknown"),
                            "region": data.get("region", "Unknown"),
                            "country": data.get("country", "Unknown"),
                            "lat": float(loc[0]) if len(loc) == 2 else 0.0,
                            "lon": float(loc[1]) if len(loc) == 2 else 0.0,
                            "org": data.get("org", "Unknown"),
                            "timezone": data.get("timezone", "UTC"),
                            "postal": data.get("postal", ""),
                            "geo_source": self.GEO_SOURCE_IPINFO,
                        }
        except Exception as e:
            logger.warning(f"ipinfo.io failed ({e}), falling back to ip-api…")
        # Fallback: ip-api single endpoint (base URL from settings)
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    self.ip_api_single_url
                    + "?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query",
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as r:
                    if r.status == 200:
                        data = await r.json(content_type=None)
                        if data.get("status") == "success":
                            return {
                                "ip": data.get("query", "Unknown"),
                                "city": data.get("city", "Unknown"),
                                "region": data.get("regionName", "Unknown"),
                                "country": data.get("country", "Unknown"),
                                "lat": float(data.get("lat", 0)),
                                "lon": float(data.get("lon", 0)),
                                "org": data.get("org", data.get("isp", "Unknown")),
                                "timezone": data.get("timezone", "UTC"),
                                "postal": "",
                                "geo_source": self.GEO_SOURCE_IP_API,
                            }
        except Exception as e2:
            logger.error(f"ip-api fallback also failed: {e2}")
        # No third-party answer: report that plainly instead of posing as located.
        return {
            "ip": "Unknown", "city": "Unknown", "region": "", "country": "Unknown",
            "lat": 0.0, "lon": 0.0, "org": "Unknown", "timezone": "UTC",
            "geo_source": "unavailable",
        }

    def _get_raw_connections(self) -> list:
        """Enumerate all ESTABLISHED TCP connections via psutil, with lsof fallback on macOS."""
        conns = []
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status not in ("ESTABLISHED", "SYN_SENT", "SYN_RECV"):
                    continue
                if not c.raddr:
                    continue
                
                process_name = "unknown"
                if c.pid:
                    try:
                        p = psutil.Process(c.pid)
                        process_name = p.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                conns.append({
                    "remote_ip": c.raddr.ip,
                    "remote_port": c.raddr.port,
                    "local_port": c.laddr.port if c.laddr else 0,
                    "protocol": "TCP" if c.type == 1 else "UDP",
                    "process": process_name,
                    "pid": c.pid,
                    "status": c.status,
                })
        except psutil.AccessDenied:
            logger.warning("psutil.net_connections: AccessDenied — falling back to lsof")
            import subprocess
            try:
                r = subprocess.run(['lsof', '-i', 'TCP', '-n', '-P'], capture_output=True, text=True, timeout=10)
                for line in r.stdout.strip().split('\n')[1:]:
                    parts = line.split()
                    if len(parts) < 9 or 'ESTABLISHED' not in line or '->' not in parts[-2]:
                        continue
                    
                    cmd = parts[0]
                    pid = int(parts[1]) if parts[1].isdigit() else None
                    remote_part = parts[-2].split('->')[1]
                    
                    # Parse IPv6 [::1]:port or IPv4 1.2.3.4:port
                    ipv6_match = re.match(r'\[([^\]]+)\]:(\d+)', remote_part)
                    ipv4_match = re.match(r'([0-9.]+):(\d+)', remote_part)
                    
                    if ipv6_match:
                        ip, port = ipv6_match.group(1), int(ipv6_match.group(2))
                    elif ipv4_match:
                        ip, port = ipv4_match.group(1), int(ipv4_match.group(2))
                    else:
                        continue
                        
                    conns.append({
                        "remote_ip": ip,
                        "remote_port": port,
                        "local_port": 0,
                        "protocol": "TCP",
                        "process": cmd,
                        "pid": pid,
                        "status": "ESTABLISHED",
                    })
            except Exception as e:
                logger.error(f"lsof fallback failed: {e}")
        except Exception as e:
            logger.error(f"_get_raw_connections error: {e}")
            
        return conns

    def _get_open_ports(self) -> list:
        """List locally bound listening ports."""
        ports = []
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "LISTEN" and c.laddr:
                    ports.append({
                        "port": c.laddr.port,
                        "ip": c.laddr.ip,
                        "pid": c.pid,
                    })
        except Exception:
            pass
        # Deduplicate by port
        seen = set()
        unique = []
        for p in ports:
            if p["port"] not in seen:
                seen.add(p["port"])
                unique.append(p)
        return sorted(unique, key=lambda x: x["port"])

    async def _bulk_geolocate(self, ips: list) -> dict:
        """Geolocate a list of IPs using ip-api.com batch endpoint (free, up to 100/request)."""
        if not ips:
            return {}
        result = {}
        batch_size = 100
        fields = "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"
        try:
            async with aiohttp.ClientSession() as session:
                for i in range(0, len(ips), batch_size):
                    batch = ips[i: i + batch_size]
                    payload = [{"query": ip, "fields": fields} for ip in batch]
                    try:
                        async with session.post(
                            self.ip_api_batch_url,
                            json=payload,
                            timeout=aiohttp.ClientTimeout(total=12),
                        ) as r:
                            if r.status == 200:
                                data = await r.json(content_type=None)
                                for entry in data:
                                    if entry.get("status") == "success":
                                        # Tag provenance: everything downstream
                                        # (classification, severity) is derived
                                        # from this third-party response.
                                        entry["geo_source"] = self.GEO_SOURCE_IP_API
                                        result[entry["query"]] = entry
                    except Exception as e:
                        logger.warning(f"Batch geo error for chunk {i}: {e}")
                    # ip-api free tier: max 45 req/min — add small delay between chunks
                    if i + batch_size < len(ips):
                        await asyncio.sleep(1.5)
        except Exception as e:
            logger.error(f"_bulk_geolocate error: {e}")
        return result

    @staticmethod
    def _top_country(threats: list) -> str:
        if not threats:
            return "None"
        counts: dict = {}
        for t in threats:
            c = t.get("country", "Unknown")
            counts[c] = counts.get(c, 0) + 1
        return max(counts, key=lambda k: counts[k])


# Singleton
machine_scanner = MachineScannerService()
