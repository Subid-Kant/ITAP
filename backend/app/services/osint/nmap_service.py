"""
ITAP — Nmap Active Scanning Service v1.0
Layer 1.5: Active port scanning, service version detection, OS fingerprinting,
and NSE vulnerability script execution via the locally installed Nmap binary.

This module wraps python-nmap and runs scans asynchronously via asyncio.to_thread
so the main FastAPI event loop is never blocked.
"""
import asyncio
import nmap
import logging
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
from app.core.config import settings

logger = logging.getLogger("itap.nmap")

# Path to nmap binary — configured via settings (from .env NMAP_PATH)
NMAP_PATH = settings.NMAP_PATH


class NmapService:
    """
    Active network scanner powered by Nmap + NSE.
    Provides real-time, ground-truth port/service/vulnerability data
    that overrides and verifies cached OSINT intelligence.
    """

    @staticmethod
    def _get_scanner() -> nmap.PortScanner:
        """Create a PortScanner instance pointed at the correct binary."""
        scanner = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))
        return scanner

    @staticmethod
    def _run_scan_sync(
        target: str,
        scan_type: str = "standard",
        ports: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Synchronous scan worker — runs in a thread via asyncio.to_thread.

        scan_type options:
          - "quick"    : Top 100 ports, service version detection
          - "standard" : Top 1000 ports, service version, OS detection
          - "deep"     : All ports + NSE vuln scripts (slow but thorough)
        """
        scanner = NmapService._get_scanner()
        scan_start = datetime.utcnow()

        # Build scan arguments based on type
        # Note: Avoid '-p-' (65,535 ports) as it can take 30-60+ mins over the internet.
        # Top 1000 ports cover >93% of open services and finish in 1-2 minutes.
        if scan_type == "quick":
            arguments = "-sV -T4 --top-ports 100 --host-timeout 2m"
        elif scan_type == "deep":
            arguments = "-sV --script vuln -T4 --top-ports 1000 --script-timeout 30s --host-timeout 5m"
            if ports:
                arguments = f"-sV --script vuln -T4 -p {ports} --script-timeout 30s --host-timeout 5m"
        else:  # standard
            arguments = "-sV -O -T4 --top-ports 1000 --host-timeout 3m"
            if ports:
                arguments = f"-sV -O -T4 -p {ports} --host-timeout 3m"

        import socket
        scan_host = target.strip()
        try:
            # Resolve domain to IP so Nmap doesn't warn or fail on multi-IP CDN domains
            scan_host = socket.gethostbyname(scan_host)
            logger.info(f"Resolved {target} -> {scan_host}")
        except Exception:
            scan_host = target.strip()

        logger.info(f"Nmap scan starting: {target} ({scan_host}) | type={scan_type} | args={arguments}")

        try:
            scanner.scan(hosts=scan_host, arguments=arguments)
        except nmap.PortScannerError as e:
            # If scanner still populated host data despite warnings on stderr, don't fail
            if not scanner.all_hosts():
                logger.error(f"Nmap scan error for {target}: {e}")
                return {
                    "status": "error",
                    "error": str(e),
                    "target": target,
                    "scan_type": scan_type,
                }
        except Exception as e:
            logger.error(f"Unexpected Nmap error for {target}: {e}")
            return {
                "status": "error",
                "error": str(e),
                "target": target,
                "scan_type": scan_type,
            }

        scan_end = datetime.utcnow()
        duration = (scan_end - scan_start).total_seconds()

        # Parse results
        all_hosts = scanner.all_hosts()
        if not all_hosts:
            logger.warning(f"Nmap returned no hosts for {target}")
            return {
                "status": "completed",
                "target": target,
                "scan_type": scan_type,
                "duration_seconds": duration,
                "hosts": [],
                "open_ports": [],
                "services": [],
                "vulnerabilities": [],
                "os_detection": None,
                "nmap_command": scanner.command_line(),
            }

        results = {
            "status": "completed",
            "target": target,
            "scan_type": scan_type,
            "duration_seconds": round(duration, 2),
            "scan_timestamp": scan_start.isoformat(),
            "hosts": [],
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "os_detection": None,
            "nmap_command": scanner.command_line(),
        }

        for host in all_hosts:
            host_data = scanner[host]
            host_info = {
                "ip": host,
                "hostnames": [h["name"] for h in host_data.hostnames() if h["name"]],
                "state": host_data.state(),
            }
            results["hosts"].append(host_info)

            # OS Detection
            if "osmatch" in host_data and host_data["osmatch"]:
                best_os = host_data["osmatch"][0]
                results["os_detection"] = {
                    "name": best_os.get("name", "Unknown"),
                    "accuracy": int(best_os.get("accuracy", 0)),
                    "os_family": best_os.get("osclass", [{}])[0].get("osfamily", "") if best_os.get("osclass") else "",
                    "os_gen": best_os.get("osclass", [{}])[0].get("osgen", "") if best_os.get("osclass") else "",
                }

            # Iterate protocols (tcp, udp)
            for proto in host_data.all_protocols():
                ports = host_data[proto].keys()
                for port in sorted(ports):
                    port_data = host_data[proto][port]

                    if port_data["state"] != "open":
                        continue

                    results["open_ports"].append(port)

                    service_entry = {
                        "port": port,
                        "transport": proto,
                        "state": port_data["state"],
                        "service": port_data.get("name", "unknown"),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", ""),
                        "extra_info": port_data.get("extrainfo", ""),
                        "cpe": port_data.get("cpe", ""),
                        "banner": f"{port_data.get('product', '')} {port_data.get('version', '')} {port_data.get('extrainfo', '')}".strip(),
                        "verified": True,  # This is actively verified, not cached
                    }
                    results["services"].append(service_entry)

                    # Parse NSE script output for vulnerabilities
                    if "script" in port_data:
                        for script_name, script_output in port_data["script"].items():
                            vuln = NmapService._parse_nse_output(
                                script_name, script_output, port, proto, host
                            )
                            if vuln:
                                results["vulnerabilities"].append(vuln)

        # De-duplicate ports
        results["open_ports"] = sorted(list(set(results["open_ports"])))

        logger.info(
            f"Nmap scan completed: {target} | "
            f"{len(results['open_ports'])} ports, "
            f"{len(results['services'])} services, "
            f"{len(results['vulnerabilities'])} vulns | "
            f"{duration:.1f}s"
        )

        return results

    @staticmethod
    def _parse_nse_output(
        script_name: str, output: str, port: int, proto: str, host: str
    ) -> Optional[Dict[str, Any]]:
        """Parse NSE script output into structured vulnerability data."""
        if not output or output.strip() == "":
            return None

        # Skip informational scripts that don't report vulns
        skip_scripts = {"http-server-header", "http-title", "ssl-date", "ssh-hostkey"}
        if script_name in skip_scripts:
            return None

        output_lower = output.lower()

        # Reject negative/clean script results (e.g. "Couldn't find any stored XSS vulnerabilities")
        negative_indicators = [
            "couldn't find",
            "could not find",
            "not vulnerable",
            "not affected",
            "no vulnerabilities",
            "no vulnerability",
            "did not find",
            "false positive",
            "clean",
            "safe",
        ]
        is_explicitly_safe = any(neg in output_lower for neg in negative_indicators)
        is_explicitly_vulnerable = (
            "state: vulnerable" in output_lower or
            "state: likely vulnerable" in output_lower or
            "state: exploitable" in output_lower
        )

        if is_explicitly_safe and not is_explicitly_vulnerable:
            return None

        # Extract CVE IDs from output
        import re
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
        cve_ids = list(set(cve_pattern.findall(output)))

        # Must have either explicit vulnerability state, CVEs, or clear vulnerability indicator
        vuln_indicators = [
            "state: vulnerable", "state: likely vulnerable", "state: exploitable",
            "vulnerable:", "exploit:", "is vulnerable", "confirmed vulnerable"
        ]
        is_vuln = any(ind in output_lower for ind in vuln_indicators)

        if not is_vuln and not cve_ids:
            return None

        # Determine severity from script output
        severity = "MEDIUM"
        cvss_score = 5.0

        if "vulnerable" in output_lower or "exploit" in output_lower:
            severity = "HIGH"
            cvss_score = 7.5
        if "critical" in output_lower or "remote code execution" in output_lower or "rce" in output_lower:
            severity = "CRITICAL"
            cvss_score = 9.8

        return {
            "source": "nmap_nse",
            "script": script_name,
            "port": port,
            "transport": proto,
            "host": host,
            "severity": severity,
            "cvss_score": cvss_score,
            "cve_ids": cve_ids,
            "description": output.strip()[:500],
            "verified": True,
            "verification_method": f"Nmap NSE script: {script_name}",
            "exact_location": f"{host}:{port}/{proto}",
        }

    @staticmethod
    async def scan(
        target: str,
        scan_type: str = "standard",
        ports: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Async wrapper — runs the blocking Nmap scan in a thread pool.
        This is the main entry point for use in async FastAPI routes.
        """
        return await asyncio.to_thread(
            NmapService._run_scan_sync, target, scan_type, ports
        )

    @staticmethod
    def merge_with_osint(
        nmap_results: Dict[str, Any],
        osint_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Merge Nmap active scan data with passive OSINT data.
        Nmap data OVERRIDES Shodan for ports/services it has verified.
        OSINT data fills gaps for things Nmap can't see (reputation, threat intel, etc.)
        """
        if nmap_results.get("status") != "completed":
            # If Nmap failed, return OSINT as-is with a flag
            osint_results["nmap"] = {
                "status": "error",
                "error": nmap_results.get("error", "Nmap scan failed"),
            }
            return osint_results

        # 1. Override ports with Nmap's verified data
        shodan_data = osint_results.get("sources", {}).get("shodan", {})
        nmap_ports = set(nmap_results.get("open_ports", []))
        shodan_ports = set(shodan_data.get("ports", []))

        # Combined ports: union of both
        combined_ports = sorted(list(nmap_ports | shodan_ports))

        # 2. Build merged services list
        nmap_services = {s["port"]: s for s in nmap_results.get("services", [])}
        osint_services = osint_results.get("vulnerabilities_by_service", [])

        # Mark existing OSINT services as verified/unverified
        for svc in osint_services:
            port = svc.get("port")
            if port in nmap_services:
                nmap_svc = nmap_services[port]
                svc["nmap_verified"] = True
                # Override with Nmap's more accurate version detection
                if nmap_svc.get("product"):
                    svc["service"] = nmap_svc["product"]
                if nmap_svc.get("version"):
                    svc["version"] = nmap_svc["version"]
                svc["banner"] = nmap_svc.get("banner", svc.get("banner", ""))
            else:
                svc["nmap_verified"] = False

        # Add Nmap-only discovered services that OSINT missed
        osint_ports = {s.get("port") for s in osint_services}
        for port, nmap_svc in nmap_services.items():
            if port not in osint_ports:
                osint_services.append({
                    "service": nmap_svc.get("product") or nmap_svc.get("service", "unknown"),
                    "version": nmap_svc.get("version", ""),
                    "port": port,
                    "transport": nmap_svc.get("transport", "tcp"),
                    "banner": nmap_svc.get("banner", ""),
                    "risk_level": "LOW",
                    "cves": [],
                    "nmap_verified": True,
                    "nmap_only": True,  # Discovered by Nmap but not in OSINT
                })

        # 3. Add Nmap-discovered vulnerabilities
        nmap_vulns = nmap_results.get("vulnerabilities", [])

        # 4. OS detection override
        if nmap_results.get("os_detection"):
            os_det = nmap_results["os_detection"]
            osint_results.setdefault("osint_fingerprint", {})
            osint_results["osint_fingerprint"]["os_nmap"] = (
                f"{os_det['name']} (accuracy: {os_det['accuracy']}%)"
            )
            if os_det["accuracy"] > 85:
                osint_results["osint_fingerprint"]["os"] = os_det["name"]

        # 5. Update the results
        osint_results["vulnerabilities_by_service"] = osint_services
        osint_results.setdefault("sources", {}).setdefault("shodan", {})["ports"] = combined_ports

        # Update summary
        osint_results.setdefault("summary", {})["open_ports"] = len(combined_ports)

        # Add Nmap section
        osint_results["nmap"] = {
            "status": "completed",
            "scan_type": nmap_results.get("scan_type"),
            "duration_seconds": nmap_results.get("duration_seconds"),
            "scan_timestamp": nmap_results.get("scan_timestamp"),
            "ports_discovered": len(nmap_ports),
            "services_detected": len(nmap_results.get("services", [])),
            "vulnerabilities_found": len(nmap_vulns),
            "os_detection": nmap_results.get("os_detection"),
            "nmap_command": nmap_results.get("nmap_command"),
            "active_vulnerabilities": nmap_vulns,
        }

        # 6. Adjust risk score if Nmap found critical vulns
        if nmap_vulns:
            critical_count = sum(1 for v in nmap_vulns if v.get("severity") == "CRITICAL")
            high_count = sum(1 for v in nmap_vulns if v.get("severity") == "HIGH")
            nmap_risk_boost = min(critical_count * 8 + high_count * 4, 20)
            current_risk = osint_results.get("risk_score", 50)
            osint_results["risk_score"] = min(round(current_risk + nmap_risk_boost, 1), 100.0)

            # Recalculate risk level
            rs = osint_results["risk_score"]
            osint_results["risk_level"] = (
                "CRITICAL" if rs >= 85 else
                "HIGH" if rs >= 65 else
                "MEDIUM" if rs >= 40 else
                "LOW"
            )

        return osint_results
