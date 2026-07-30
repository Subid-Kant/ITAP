"""
ITAP — Global Threat Feed Service v2.0
Polls real public APIs (NVD CVEs, CISA KEV) for live global threats.
Creates incident records so the dashboard shows real worldwide activity.
Uses aiohttp for non-blocking async HTTP requests.
"""
import asyncio
import logging
import aiohttp
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.database import async_session_factory
from app.models.models import Incident, SeverityLevel, IncidentStatus

logger = logging.getLogger("itap.monitor.global")

# Approximate geo-coordinates for countries commonly listed in KEV/threat feeds
COUNTRY_COORDINATES = {
    "United States": (37.09, -95.71),
    "China": (35.86, 104.19),
    "Russia": (61.52, 105.31),
    "Iran": (32.42, 53.68),
    "North Korea": (40.33, 127.51),
    "India": (20.59, 78.96),
    "Germany": (51.16, 10.45),
    "United Kingdom": (55.37, -3.43),
    "Brazil": (-14.23, -51.92),
    "Ukraine": (48.37, 31.16),
    "Israel": (31.04, 34.85),
    "France": (46.22, 2.21),
    "Japan": (36.20, 138.25),
    "Canada": (56.13, -106.34),
    "Australia": (-25.27, 133.77),
    "Netherlands": (52.13, 5.29),
    "South Korea": (35.90, 127.76),
    "Pakistan": (30.37, 69.34),
    "Turkey": (38.96, 35.24),
    "Vietnam": (14.05, 108.27),
}

# Vendor/product to approximate attacker origin country (for KEV entries)
VENDOR_ORIGIN_COUNTRY = {
    "Microsoft": "Russia",
    "Apache": "China",
    "VMware": "Iran",
    "Cisco": "Russia",
    "Fortinet": "China",
    "Pulse Secure": "North Korea",
    "SolarWinds": "Russia",
    "Exchange": "China",
    "Log4j": "Iran",
    "MOVEit": "Russia",
    "GoAnywhere": "Russia",
    "Ivanti": "China",
}


class GlobalThreatFeed:
    def __init__(self):
        self.is_running = False
        self.cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.recent_cves_url = "https://cve.circl.lu/api/last"
        self._cache = {}
        self._cache_time = None

    async def start(self):
        self.is_running = True
        logger.info("Started real-time global threat feeds")
        asyncio.create_task(self._monitor_loop())

    async def stop(self):
        self.is_running = False
        logger.info("Stopped global threat feeds")

    async def fetch_cisa_kev(self):
        """Fetch the latest Known Exploited Vulnerabilities from CISA."""
        # Use cache if fresh (< 30 min)
        if self._cache.get("kev") and self._cache_time:
            if (datetime.utcnow() - self._cache_time).total_seconds() < 1800:
                return self._cache["kev"]
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.cisa_kev_url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        vuls = data.get("vulnerabilities", [])
                        # Sort by date added, descending
                        vuls.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
                        result = vuls[:20]  # Return latest 20
                        self._cache["kev"] = result
                        self._cache_time = datetime.utcnow()
                        return result
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV: {e}")
        return self._cache.get("kev", [])

    async def fetch_recent_cves(self):
        """Fetch recent CVEs from circl.lu."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.recent_cves_url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        return data[:15]
        except Exception as e:
            logger.error(f"Failed to fetch recent CVEs: {e}")
        return []

    def get_kev_coordinates(self, kev_entry: dict) -> tuple:
        """Estimate attacker origin coordinates for a KEV entry."""
        vendor = kev_entry.get("vendorProject", "")
        for keyword, country in VENDOR_ORIGIN_COUNTRY.items():
            if keyword.lower() in vendor.lower():
                return COUNTRY_COORDINATES.get(country, (0, 0)), country
        # Default to a generic location
        return (30.0, 50.0), "Unknown"

    async def get_current_threats(self) -> dict:
        """Get instant snapshot of global threats for the dashboard."""
        kev = await self.fetch_cisa_kev()
        cves = await self.fetch_recent_cves()

        # Enrich KEV with coordinates
        enriched_kev = []
        for v in kev:
            coords, country = self.get_kev_coordinates(v)
            enriched_kev.append({
                **v,
                "estimated_origin": country,
                "lat": coords[0],
                "lon": coords[1],
            })

        return {
            "cisa_kev": enriched_kev,
            "recent_cves": cves,
            "total_kev": len(enriched_kev),
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def _monitor_loop(self):
        while self.is_running:
            try:
                await self._process_feeds()
            except Exception as e:
                logger.error(f"Error in global threat feed loop: {e}")
            await asyncio.sleep(3600)  # Check hourly

    async def _process_feeds(self):
        kev = await self.fetch_cisa_kev()
        if not kev:
            return

        async with async_session_factory() as db:
            for v in kev[:5]:  # Process top 5 newest
                cve_id = v.get("cveID")
                title = f"[Global Intel] Active Exploitation: {cve_id} - {v.get('vulnerabilityName', 'Unknown')}"

                # Check if already exists
                stmt = select(Incident).where(Incident.title == title)
                result = await db.execute(stmt)
                existing = result.scalars().first()

                if not existing:
                    desc = (
                        f"CISA KEV Alert: {v.get('shortDescription', 'No description')}\n"
                        f"Vendor: {v.get('vendorProject', 'Unknown')} | Product: {v.get('product', 'Unknown')}\n"
                        f"Required Action: {v.get('requiredAction', 'Apply vendor patch')}\n"
                        f"Action Due: {v.get('dueDate', 'N/A')}"
                    )
                    incident = Incident(
                        title=title,
                        description=desc,
                        severity=SeverityLevel.CRITICAL,
                        status=IncidentStatus.OPEN,
                        source="global_feed",
                    )
                    db.add(incident)

            await db.commit()
            logger.info(f"Global Threat Feed: processed {len(kev[:5])} KEV entries")


global_threat_feed = GlobalThreatFeed()
