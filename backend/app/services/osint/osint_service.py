"""
ITAP — OSINT Aggregation Service
Layer 1: Unified OSINT data collection from multiple intelligence sources.
Supports Shodan, VirusTotal, CVE/NVD, AlienVault OTX, and paste monitors.
"""
import asyncio
import aiohttp
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from app.core.config import settings
import logging

logger = logging.getLogger("itap.osint")


class ShodanService:
    """Shodan API integration for exposed service discovery."""
    
    BASE_URL = "https://api.shodan.io"
    
    @staticmethod
    async def search_host(ip: str) -> Dict[str, Any]:
        """Query Shodan for host information."""
        if not settings.SHODAN_API_KEY:
            return ShodanService._mock_shodan_data(ip)
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{ShodanService.BASE_URL}/shodan/host/{ip}?key={settings.SHODAN_API_KEY}"
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            "ip": data.get("ip_str"),
                            "hostnames": data.get("hostnames", []),
                            "ports": data.get("ports", []),
                            "vulns": data.get("vulns", []),
                            "os": data.get("os"),
                            "org": data.get("org"),
                            "country": data.get("country_name"),
                            "city": data.get("city"),
                            "latitude": data.get("latitude"),
                            "longitude": data.get("longitude"),
                            "last_update": data.get("last_update"),
                            "services": [
                                {
                                    "port": svc.get("port"),
                                    "transport": svc.get("transport"),
                                    "product": svc.get("product"),
                                    "version": svc.get("version"),
                                    "banner": svc.get("data", "")[:200]
                                }
                                for svc in data.get("data", [])[:10]
                            ]
                        }
                    return {"error": f"Shodan API returned {resp.status}"}
        except Exception as e:
            logger.error(f"Shodan query failed for {ip}: {e}")
            return ShodanService._mock_shodan_data(ip)
    
    @staticmethod
    def _mock_shodan_data(ip: str) -> Dict[str, Any]:
        """Generate realistic mock data for demo purposes."""
        import random
        ports = random.sample([22, 80, 443, 8080, 3306, 5432, 6379, 27017, 8443, 9200], k=random.randint(2, 5))
        countries = [("United States", "New York", 40.7128, -74.0060),
                     ("Russia", "Moscow", 55.7558, 37.6173),
                     ("China", "Beijing", 39.9042, 116.4074),
                     ("Germany", "Berlin", 52.5200, 13.4050),
                     ("India", "Mumbai", 19.0760, 72.8777)]
        loc = random.choice(countries)
        return {
            "ip": ip,
            "hostnames": [f"host-{ip.replace('.', '-')}.example.com"],
            "ports": ports,
            "vulns": [f"CVE-2024-{random.randint(1000, 9999)}" for _ in range(random.randint(0, 3))],
            "os": random.choice(["Linux 5.x", "Windows Server 2022", "Ubuntu 22.04", "CentOS 8"]),
            "org": random.choice(["AWS", "Google Cloud", "Azure", "DigitalOcean", "OVH"]),
            "country": loc[0],
            "city": loc[1],
            "latitude": loc[2],
            "longitude": loc[3],
            "last_update": datetime.utcnow().isoformat(),
            "services": [
                {"port": p, "transport": "tcp", "product": random.choice(["nginx", "Apache", "OpenSSH", "MySQL"]),
                 "version": f"{random.randint(1,9)}.{random.randint(0,9)}", "banner": ""}
                for p in ports[:4]
            ]
        }


class VirusTotalService:
    """VirusTotal API integration for IP/domain/file reputation."""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    @staticmethod
    async def check_domain(domain: str) -> Dict[str, Any]:
        """Check domain reputation on VirusTotal."""
        if not settings.VIRUSTOTAL_API_KEY:
            return VirusTotalService._mock_vt_data(domain)
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
                url = f"{VirusTotalService.BASE_URL}/domains/{domain}"
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        attrs = data.get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        return {
                            "domain": domain,
                            "reputation": attrs.get("reputation", 0),
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "undetected": stats.get("undetected", 0),
                            "categories": attrs.get("categories", {}),
                            "whois": attrs.get("whois", "")[:500],
                            "last_analysis_date": attrs.get("last_analysis_date")
                        }
                    return {"error": f"VT API returned {resp.status}"}
        except Exception as e:
            logger.error(f"VirusTotal query failed for {domain}: {e}")
            return VirusTotalService._mock_vt_data(domain)
    
    @staticmethod
    def _mock_vt_data(domain: str) -> Dict[str, Any]:
        import random
        malicious = random.randint(0, 15)
        return {
            "domain": domain,
            "reputation": random.randint(-100, 100),
            "malicious": malicious,
            "suspicious": random.randint(0, 5),
            "harmless": random.randint(50, 80),
            "undetected": random.randint(5, 15),
            "categories": {"Forcepoint": "technology", "Sophos": "information technology"},
            "risk_level": "high" if malicious > 5 else "medium" if malicious > 2 else "low",
            "last_analysis_date": datetime.utcnow().isoformat()
        }


class CVEService:
    """CVE/NVD Feed integration for vulnerability intelligence."""
    
    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    @staticmethod
    async def search_cves(keyword: str, days: int = 30) -> List[Dict[str, Any]]:
        """Search recent CVEs related to a keyword."""
        try:
            async with aiohttp.ClientSession() as session:
                pub_start = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
                pub_end = datetime.utcnow().strftime("%Y-%m-%dT23:59:59.999")
                params = {
                    "keywordSearch": keyword,
                    "pubStartDate": pub_start,
                    "pubEndDate": pub_end,
                    "resultsPerPage": 20
                }
                async with session.get(CVEService.NVD_URL, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        cves = []
                        for item in data.get("vulnerabilities", []):
                            cve = item.get("cve", {})
                            metrics = cve.get("metrics", {})
                            cvss_data = {}
                            if "cvssMetricV31" in metrics:
                                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                            elif "cvssMetricV2" in metrics:
                                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                            
                            descriptions = cve.get("descriptions", [])
                            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
                            
                            cves.append({
                                "cve_id": cve.get("id"),
                                "description": desc[:300],
                                "cvss_score": cvss_data.get("baseScore", 0),
                                "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
                                "attack_vector": cvss_data.get("attackVector", ""),
                                "published": cve.get("published"),
                                "modified": cve.get("lastModified")
                            })
                        return cves
                    return CVEService._mock_cve_data(keyword)
        except Exception as e:
            logger.error(f"CVE search failed for {keyword}: {e}")
            return CVEService._mock_cve_data(keyword)
    
    @staticmethod
    def _mock_cve_data(keyword: str) -> List[Dict[str, Any]]:
        import random
        cves = []
        for i in range(random.randint(3, 8)):
            score = round(random.uniform(3.0, 10.0), 1)
            cves.append({
                "cve_id": f"CVE-2024-{random.randint(10000, 99999)}",
                "description": f"Vulnerability in {keyword} related component allowing remote code execution or privilege escalation.",
                "cvss_score": score,
                "severity": "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW",
                "attack_vector": random.choice(["NETWORK", "ADJACENT_NETWORK", "LOCAL"]),
                "published": (datetime.utcnow() - timedelta(days=random.randint(1, 30))).isoformat(),
                "modified": datetime.utcnow().isoformat()
            })
        return sorted(cves, key=lambda x: x["cvss_score"], reverse=True)


class AlienVaultOTXService:
    """AlienVault OTX integration for threat indicators."""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    @staticmethod
    async def get_indicators(indicator: str, indicator_type: str = "domain") -> Dict[str, Any]:
        """Get threat indicators from OTX."""
        if not settings.ALIENVAULT_OTX_KEY:
            return AlienVaultOTXService._mock_otx_data(indicator)
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"X-OTX-API-KEY": settings.ALIENVAULT_OTX_KEY}
                url = f"{AlienVaultOTXService.BASE_URL}/indicators/{indicator_type}/{indicator}/general"
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            "indicator": indicator,
                            "type": indicator_type,
                            "pulse_count": data.get("pulse_info", {}).get("count", 0),
                            "reputation": data.get("reputation", 0),
                            "sections": data.get("sections", []),
                            "pulses": [
                                {
                                    "name": p.get("name"),
                                    "description": p.get("description", "")[:200],
                                    "tags": p.get("tags", []),
                                    "created": p.get("created")
                                }
                                for p in data.get("pulse_info", {}).get("pulses", [])[:5]
                            ]
                        }
                    return {"error": f"OTX API returned {resp.status}"}
        except Exception as e:
            logger.error(f"OTX query failed for {indicator}: {e}")
            return AlienVaultOTXService._mock_otx_data(indicator)
    
    @staticmethod
    def _mock_otx_data(indicator: str) -> Dict[str, Any]:
        import random
        return {
            "indicator": indicator,
            "type": "domain",
            "pulse_count": random.randint(0, 50),
            "reputation": random.randint(0, 100),
            "sections": ["general", "geo", "malware", "url_list"],
            "pulses": [
                {
                    "name": f"Threat Campaign #{random.randint(100, 999)}",
                    "description": "Advanced persistent threat campaign targeting critical infrastructure.",
                    "tags": random.sample(["malware", "phishing", "apt", "ransomware", "c2", "botnet"], k=3),
                    "created": (datetime.utcnow() - timedelta(days=random.randint(1, 60))).isoformat()
                }
                for _ in range(random.randint(1, 4))
            ]
        }


class OSINTAggregator:
    """
    Unified OSINT aggregation orchestrator.
    Collects data from all sources and produces a consolidated threat posture.
    """
    
    @staticmethod
    async def full_scan(domain: str, ip: Optional[str] = None) -> Dict[str, Any]:
        """Run all OSINT sources in parallel and aggregate results."""
        import socket
        
        # Resolve IP if not provided
        if not ip:
            try:
                ip = socket.gethostbyname(domain)
            except socket.gaierror:
                ip = "0.0.0.0"
        
        # Run all sources concurrently
        shodan_task = ShodanService.search_host(ip)
        vt_task = VirusTotalService.check_domain(domain)
        cve_task = CVEService.search_cves(domain)
        otx_task = AlienVaultOTXService.get_indicators(domain)
        
        results = await asyncio.gather(
            shodan_task, vt_task, cve_task, otx_task,
            return_exceptions=True
        )
        
        shodan_data = results[0] if not isinstance(results[0], Exception) else {}
        vt_data = results[1] if not isinstance(results[1], Exception) else {}
        cve_data = results[2] if not isinstance(results[2], Exception) else []
        otx_data = results[3] if not isinstance(results[3], Exception) else {}
        
        # Calculate composite risk score
        risk_score = OSINTAggregator._calculate_risk_score(shodan_data, vt_data, cve_data, otx_data)
        
        return {
            "domain": domain,
            "ip": ip,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "risk_score": risk_score,
            "risk_level": "CRITICAL" if risk_score >= 85 else "HIGH" if risk_score >= 65 else "MEDIUM" if risk_score >= 40 else "LOW",
            "sources": {
                "shodan": shodan_data,
                "virustotal": vt_data,
                "cve_nvd": cve_data,
                "alienvault_otx": otx_data
            },
            "summary": {
                "open_ports": len(shodan_data.get("ports", [])),
                "known_vulns": len(shodan_data.get("vulns", [])),
                "vt_malicious": vt_data.get("malicious", 0),
                "recent_cves": len(cve_data) if isinstance(cve_data, list) else 0,
                "otx_pulses": otx_data.get("pulse_count", 0),
                "geolocation": {
                    "country": shodan_data.get("country"),
                    "city": shodan_data.get("city"),
                    "lat": shodan_data.get("latitude"),
                    "lon": shodan_data.get("longitude")
                }
            }
        }
    
    @staticmethod
    def _calculate_risk_score(shodan: Dict, vt: Dict, cves: List, otx: Dict) -> float:
        """Compute a composite risk score (0-100) from all OSINT sources."""
        score = 0.0
        
        # Shodan: open ports and vulns
        ports = len(shodan.get("ports", []))
        vulns = len(shodan.get("vulns", []))
        score += min(ports * 3, 15)  # max 15 from ports
        score += min(vulns * 8, 25)  # max 25 from vulns
        
        # VirusTotal: malicious detections
        malicious = vt.get("malicious", 0)
        score += min(malicious * 4, 25)  # max 25 from VT
        
        # CVEs: high severity CVEs
        if isinstance(cves, list):
            critical_cves = sum(1 for c in cves if c.get("cvss_score", 0) >= 9.0)
            high_cves = sum(1 for c in cves if 7.0 <= c.get("cvss_score", 0) < 9.0)
            score += min(critical_cves * 6 + high_cves * 3, 20)  # max 20 from CVEs
        
        # OTX: pulse count
        pulses = otx.get("pulse_count", 0)
        score += min(pulses * 2, 15)  # max 15 from OTX
        
        return min(round(score, 1), 100.0)
