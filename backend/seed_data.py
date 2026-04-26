"""
ITAP — Database Seeder
Populates the database with realistic threat intelligence data
so the dashboard shows real live data from the backend.
"""
import asyncio
import uuid
import random
from datetime import datetime, timedelta

# Setup path
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from app.db.database import engine, async_session_factory, Base
from app.models.models import (
    Target, Scan, Threat, Incident, RemediationLog,
    SeverityLevel, ScanStatus, IncidentStatus
)

# Realistic threat data
TARGETS = [
    {"domain": "webapp.example.com", "ip": "203.0.113.42", "org": "TechCorp Inc."},
    {"domain": "api.financeapp.io", "ip": "198.51.100.17", "org": "FinanceApp Ltd."},
    {"domain": "portal.healthcare.org", "ip": "192.0.2.88", "org": "HealthCare Systems"},
    {"domain": "mail.enterprise.net", "ip": "203.0.113.99", "org": "Enterprise Networks"},
    {"domain": "cdn.mediahost.com", "ip": "198.51.100.55", "org": "MediaHost Global"},
    {"domain": "db.cloudstore.io", "ip": "192.0.2.201", "org": "CloudStore Services"},
]

THREAT_DATA = [
    {
        "title": "CVE-2024-21762: FortiOS RCE — Active Exploitation",
        "desc": "Critical out-of-bounds write in FortiOS SSL VPN. Actively exploited in the wild by APT groups. CVSS 9.8. Immediate patching required.",
        "severity": SeverityLevel.CRITICAL, "score": 9.8, "category": "Remote Code Execution",
        "tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
        "phase": "Initial Access", "country": "Russia", "lat": 55.75, "lon": 37.61
    },
    {
        "title": "Lazarus Group C2 Beacon — DNS Tunneling Detected",
        "desc": "Encoded DNS queries to known Lazarus Group infrastructure. Beaconing pattern matches DPRK APT tradecraft. Exfiltration suspected.",
        "severity": SeverityLevel.CRITICAL, "score": 9.5, "category": "C2 Communication",
        "tactic": "Command and Control", "technique_id": "T1071", "technique_name": "Application Layer Protocol",
        "phase": "Command and Control", "country": "North Korea", "lat": 39.03, "lon": 125.75
    },
    {
        "title": "SQL Injection on /api/v2/users — Data Breach Risk",
        "desc": "Automated SQLi attack targeting user authentication endpoint. UNION-based injection confirmed. 47K records potentially exposed.",
        "severity": SeverityLevel.CRITICAL, "score": 9.2, "category": "SQL Injection",
        "tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
        "phase": "Initial Access", "country": "China", "lat": 39.90, "lon": 116.40
    },
    {
        "title": "Ransomware Pre-Deployment — Cobalt Strike Detected",
        "desc": "Cobalt Strike beacon identified on internal server. Lateral movement in progress. LockBit 3.0 deployment imminent based on TTPs.",
        "severity": SeverityLevel.CRITICAL, "score": 9.7, "category": "Ransomware",
        "tactic": "Execution", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter",
        "phase": "Execution", "country": "Russia", "lat": 59.93, "lon": 30.31
    },
    {
        "title": "Spearphishing Campaign — CEO Impersonation",
        "desc": "Targeted phishing emails impersonating CEO sent to finance dept. Malicious .docm attachment with macro dropper. 3 users clicked.",
        "severity": SeverityLevel.HIGH, "score": 8.1, "category": "Phishing",
        "tactic": "Initial Access", "technique_id": "T1566", "technique_name": "Phishing",
        "phase": "Initial Access", "country": "Iran", "lat": 35.68, "lon": 51.38
    },
    {
        "title": "CVE-2024-3094: XZ Utils Backdoor — Supply Chain",
        "desc": "Compromised XZ Utils version detected on 3 servers. Backdoor allows SSH authentication bypass. Nation-state supply chain attack.",
        "severity": SeverityLevel.HIGH, "score": 8.8, "category": "Supply Chain Attack",
        "tactic": "Persistence", "technique_id": "T1543", "technique_name": "Create or Modify System Process",
        "phase": "Persistence", "country": "Unknown", "lat": 52.52, "lon": 13.40
    },
    {
        "title": "Brute Force SSH — 12K Attempts in 1 Hour",
        "desc": "Massive credential stuffing attack on SSH port 22. Source botnet spans 847 unique IPs. Rate: 200 attempts/minute.",
        "severity": SeverityLevel.HIGH, "score": 7.5, "category": "Brute Force",
        "tactic": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force",
        "phase": "Credential Access", "country": "Brazil", "lat": -23.55, "lon": -46.63
    },
    {
        "title": "Privilege Escalation via Kernel Exploit — CVE-2024-1086",
        "desc": "Linux kernel use-after-free in nf_tables. Local attacker achieved root. Detected via anomalous syscall pattern.",
        "severity": SeverityLevel.HIGH, "score": 7.8, "category": "Privilege Escalation",
        "tactic": "Privilege Escalation", "technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation",
        "phase": "Privilege Escalation", "country": "Germany", "lat": 52.52, "lon": 13.40
    },
    {
        "title": "Data Exfiltration — 2.3GB via HTTPS to Cloud Storage",
        "desc": "Anomalous outbound HTTPS traffic to external cloud endpoint. Volume: 2.3GB in 45 minutes. Pattern matches staged exfil.",
        "severity": SeverityLevel.HIGH, "score": 8.4, "category": "Data Exfiltration",
        "tactic": "Exfiltration", "technique_id": "T1567", "technique_name": "Exfiltration Over Web Service",
        "phase": "Exfiltration", "country": "United States", "lat": 37.77, "lon": -122.41
    },
    {
        "title": "XSS Stored — Admin Panel Compromise",
        "desc": "Persistent XSS injected into admin dashboard comment field. Session tokens of 5 admin users harvested.",
        "severity": SeverityLevel.MEDIUM, "score": 6.1, "category": "Cross-Site Scripting",
        "tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
        "phase": "Initial Access", "country": "India", "lat": 19.07, "lon": 72.87
    },
    {
        "title": "Cryptominer Deployed — XMRig on Web Server",
        "desc": "Cryptocurrency miner consuming 90% CPU on production web server. Deployed via compromised Jenkins instance.",
        "severity": SeverityLevel.MEDIUM, "score": 5.8, "category": "Resource Hijacking",
        "tactic": "Impact", "technique_id": "T1496", "technique_name": "Resource Hijacking",
        "phase": "Impact", "country": "Romania", "lat": 44.43, "lon": 26.10
    },
    {
        "title": "DDoS Attack — 45Gbps Volumetric Flood",
        "desc": "UDP amplification attack peaking at 45Gbps. Origin: Mirai botnet variant. Affecting CDN edge nodes.",
        "severity": SeverityLevel.MEDIUM, "score": 6.5, "category": "Denial of Service",
        "tactic": "Impact", "technique_id": "T1498", "technique_name": "Network Denial of Service",
        "phase": "Impact", "country": "Vietnam", "lat": 21.02, "lon": 105.83
    },
    {
        "title": "Suspicious DNS Queries — Possible DGA Activity",
        "desc": "Machine-generated domain names detected in DNS logs. Pattern consistent with Domain Generation Algorithm malware.",
        "severity": SeverityLevel.MEDIUM, "score": 5.5, "category": "Suspicious Activity",
        "tactic": "Command and Control", "technique_id": "T1568", "technique_name": "Dynamic Resolution",
        "phase": "Command and Control", "country": "Ukraine", "lat": 50.45, "lon": 30.52
    },
    {
        "title": "Port Scan — Full TCP Sweep from Single IP",
        "desc": "Complete TCP port scan (1-65535) from 185.220.101.x. Tor exit node. Reconnaissance phase activity.",
        "severity": SeverityLevel.LOW, "score": 3.2, "category": "Reconnaissance",
        "tactic": "Reconnaissance", "technique_id": "T1595", "technique_name": "Active Scanning",
        "phase": "Reconnaissance", "country": "Netherlands", "lat": 52.37, "lon": 4.89
    },
    {
        "title": "Outdated SSL Certificate — Weak Cipher Suite",
        "desc": "TLS 1.0 with RC4 cipher still enabled on legacy endpoint. Information disclosure risk. Certificate expires in 7 days.",
        "severity": SeverityLevel.LOW, "score": 2.8, "category": "Misconfiguration",
        "tactic": "Reconnaissance", "technique_id": "T1592", "technique_name": "Gather Victim Host Information",
        "phase": "Reconnaissance", "country": "United States", "lat": 40.71, "lon": -74.00
    },
]

INCIDENT_DATA = [
    {"title": "CRITICAL: Active RCE Exploitation on FortiOS VPN", "severity": SeverityLevel.CRITICAL, "status": IncidentStatus.OPEN},
    {"title": "Lazarus Group Intrusion — C2 Channel Active", "severity": SeverityLevel.CRITICAL, "status": IncidentStatus.INVESTIGATING},
    {"title": "SQL Injection Data Breach — 47K Records", "severity": SeverityLevel.CRITICAL, "status": IncidentStatus.OPEN},
    {"title": "Ransomware Pre-Deployment Detected", "severity": SeverityLevel.CRITICAL, "status": IncidentStatus.INVESTIGATING},
    {"title": "Spearphishing Campaign — 3 Users Compromised", "severity": SeverityLevel.HIGH, "status": IncidentStatus.INVESTIGATING},
    {"title": "Supply Chain Attack — XZ Utils Backdoor", "severity": SeverityLevel.HIGH, "status": IncidentStatus.OPEN},
    {"title": "Brute Force Attack — SSH Credential Stuffing", "severity": SeverityLevel.HIGH, "status": IncidentStatus.CONTAINED},
    {"title": "Data Exfiltration — 2.3GB to External Cloud", "severity": SeverityLevel.HIGH, "status": IncidentStatus.OPEN},
    {"title": "DDoS Mitigation — 45Gbps UDP Flood", "severity": SeverityLevel.MEDIUM, "status": IncidentStatus.RESOLVED},
    {"title": "Cryptominer Remediation — XMRig Removal", "severity": SeverityLevel.MEDIUM, "status": IncidentStatus.RESOLVED},
]


async def seed():
    """Seed the database with realistic threat data."""
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_factory() as db:
        print("🌱 Seeding ITAP database...")

        # Create targets
        target_ids = []
        for t in TARGETS:
            target = Target(id=str(uuid.uuid4()), domain=t["domain"], ip_address=t["ip"], organization=t["org"])
            db.add(target)
            target_ids.append(target.id)
        print(f"  ✓ Created {len(TARGETS)} targets")

        # Create threats
        threat_ids = []
        for i, td in enumerate(THREAT_DATA):
            hours_ago = random.uniform(0.5, 72)
            threat = Threat(
                id=str(uuid.uuid4()),
                target_id=target_ids[i % len(target_ids)],
                title=td["title"],
                description=td["desc"],
                severity=td["severity"],
                severity_score=td["score"],
                category=td["category"],
                mitre_tactic=td["tactic"],
                mitre_technique_id=td["technique_id"],
                mitre_technique_name=td["technique_name"],
                kill_chain_phase=td["phase"],
                source_country=td["country"],
                source_latitude=td["lat"],
                source_longitude=td["lon"],
                ioc_type="ip",
                ioc_value=f"{random.randint(100,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                is_resolved=False,
                detected_at=datetime.utcnow() - timedelta(hours=hours_ago)
            )
            db.add(threat)
            threat_ids.append(threat.id)
        print(f"  ✓ Created {len(THREAT_DATA)} threats with MITRE ATT&CK mapping")

        # Create incidents with playbooks
        for i, inc in enumerate(INCIDENT_DATA):
            incident = Incident(
                id=str(uuid.uuid4()),
                target_id=target_ids[i % len(target_ids)],
                threat_id=threat_ids[i % len(threat_ids)] if i < len(threat_ids) else None,
                title=inc["title"],
                description=f"Auto-generated incident from threat detection pipeline.",
                severity=inc["severity"],
                status=inc["status"],
                playbook_content=f"# {inc['title']}\n\nAuto-generated playbook for this incident.",
                playbook_steps=[
                    {"step_number": 1, "action": "Assess Impact", "detail": "Determine scope and affected systems."},
                    {"step_number": 2, "action": "Contain Threat", "detail": "Isolate affected systems and block IOCs."},
                    {"step_number": 3, "action": "Eradicate", "detail": "Remove malware and patch vulnerabilities."},
                    {"step_number": 4, "action": "Recover", "detail": "Restore services and verify integrity."},
                ],
                alert_sent=inc["severity"] in [SeverityLevel.CRITICAL, SeverityLevel.HIGH],
                alert_channels=["email", "webhook"] if inc["severity"] == SeverityLevel.CRITICAL else ["log"],
                detected_at=datetime.utcnow() - timedelta(hours=random.uniform(1, 48)),
            )
            if inc["status"] == IncidentStatus.INVESTIGATING:
                incident.acknowledged_at = incident.detected_at + timedelta(minutes=random.randint(5, 30))
            if inc["status"] in [IncidentStatus.CONTAINED, IncidentStatus.RESOLVED]:
                incident.acknowledged_at = incident.detected_at + timedelta(minutes=5)
                incident.contained_at = incident.detected_at + timedelta(hours=random.uniform(1, 4))
            if inc["status"] == IncidentStatus.RESOLVED:
                incident.resolved_at = incident.detected_at + timedelta(hours=random.uniform(4, 24))
            db.add(incident)
        print(f"  ✓ Created {len(INCIDENT_DATA)} incidents with playbooks")

        await db.commit()
        print("✅ Database seeded successfully!")
        print(f"   → {len(TARGETS)} targets")
        print(f"   → {len(THREAT_DATA)} threats (4 critical, 5 high, 4 medium, 2 low)")
        print(f"   → {len(INCIDENT_DATA)} incidents (4 open, 4 investigating, 1 contained, 1 resolved)")
        print(f"   → MITRE ATT&CK: 9 tactics covered")
        print(f"   → Geolocation: 12 countries mapped")


if __name__ == "__main__":
    asyncio.run(seed())
