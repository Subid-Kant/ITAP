"""
ITAP — Threat Intelligence Service v2.0
Layer 3: MITRE ATT&CK Mapping, Kill-Chain Reconstruction,
Threat DNA Fingerprinting, IOC Enrichment, and APT Actor Database.
"""
import hashlib
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("itap.threat_intel")


# ─────────────────────────────────────────────
# MITRE ATT&CK Enterprise Knowledge Base (v14)
# ─────────────────────────────────────────────

MITRE_ATTACK_MATRIX = {
    "Reconnaissance": {
        "id": "TA0043",
        "techniques": [
            {"id": "T1595", "name": "Active Scanning",
             "subtechniques": ["T1595.001 - Scanning IP Blocks", "T1595.002 - Vulnerability Scanning", "T1595.003 - Wordlist Scanning"]},
            {"id": "T1592", "name": "Gather Victim Host Information",
             "subtechniques": ["T1592.001 - Hardware", "T1592.002 - Software", "T1592.004 - Client Configurations"]},
            {"id": "T1589", "name": "Gather Victim Identity Information"},
            {"id": "T1590", "name": "Gather Victim Network Information"},
            {"id": "T1597", "name": "Search Closed Sources"},
            {"id": "T1598", "name": "Phishing for Information"},
        ],
    },
    "Resource Development": {
        "id": "TA0042",
        "techniques": [
            {"id": "T1583", "name": "Acquire Infrastructure",
             "subtechniques": ["T1583.001 - Domains", "T1583.002 - DNS Server", "T1583.003 - VPS"]},
            {"id": "T1587", "name": "Develop Capabilities",
             "subtechniques": ["T1587.001 - Malware", "T1587.002 - Code Signing Certificates", "T1587.003 - Digital Certificates"]},
            {"id": "T1588", "name": "Obtain Capabilities",
             "subtechniques": ["T1588.001 - Malware", "T1588.002 - Tool", "T1588.005 - Exploits"]},
            {"id": "T1608", "name": "Stage Capabilities"},
        ],
    },
    "Initial Access": {
        "id": "TA0001",
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1566", "name": "Phishing",
             "subtechniques": ["T1566.001 - Spearphishing Attachment", "T1566.002 - Spearphishing Link", "T1566.003 - Spearphishing via Service"]},
            {"id": "T1078", "name": "Valid Accounts",
             "subtechniques": ["T1078.001 - Default Accounts", "T1078.002 - Domain Accounts", "T1078.003 - Local Accounts"]},
            {"id": "T1133", "name": "External Remote Services"},
            {"id": "T1189", "name": "Drive-by Compromise"},
            {"id": "T1199", "name": "Trusted Relationship"},
            {"id": "T1200", "name": "Hardware Additions"},
        ],
    },
    "Execution": {
        "id": "TA0002",
        "techniques": [
            {"id": "T1059", "name": "Command and Scripting Interpreter",
             "subtechniques": ["T1059.001 - PowerShell", "T1059.003 - Windows Command Shell", "T1059.004 - Unix Shell", "T1059.006 - Python"]},
            {"id": "T1203", "name": "Exploitation for Client Execution"},
            {"id": "T1204", "name": "User Execution",
             "subtechniques": ["T1204.001 - Malicious Link", "T1204.002 - Malicious File"]},
            {"id": "T1047", "name": "Windows Management Instrumentation"},
            {"id": "T1053", "name": "Scheduled Task/Job"},
        ],
    },
    "Persistence": {
        "id": "TA0003",
        "techniques": [
            {"id": "T1098", "name": "Account Manipulation"},
            {"id": "T1136", "name": "Create Account",
             "subtechniques": ["T1136.001 - Local Account", "T1136.002 - Domain Account"]},
            {"id": "T1543", "name": "Create or Modify System Process",
             "subtechniques": ["T1543.002 - Systemd Service", "T1543.003 - Windows Service"]},
            {"id": "T1053", "name": "Scheduled Task/Job"},
            {"id": "T1505", "name": "Server Software Component",
             "subtechniques": ["T1505.003 - Web Shell"]},
            {"id": "T1574", "name": "Hijack Execution Flow"},
        ],
    },
    "Privilege Escalation": {
        "id": "TA0004",
        "techniques": [
            {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
            {"id": "T1548", "name": "Abuse Elevation Control Mechanism",
             "subtechniques": ["T1548.001 - Setuid and Setgid", "T1548.002 - Bypass User Account Control"]},
            {"id": "T1134", "name": "Access Token Manipulation"},
            {"id": "T1611", "name": "Escape to Host"},
        ],
    },
    "Defense Evasion": {
        "id": "TA0005",
        "techniques": [
            {"id": "T1027", "name": "Obfuscated Files or Information",
             "subtechniques": ["T1027.002 - Software Packing", "T1027.005 - Indicator Removal from Tools"]},
            {"id": "T1070", "name": "Indicator Removal",
             "subtechniques": ["T1070.001 - Clear Windows Event Logs", "T1070.004 - File Deletion"]},
            {"id": "T1036", "name": "Masquerading"},
            {"id": "T1218", "name": "System Binary Proxy Execution"},
            {"id": "T1562", "name": "Impair Defenses",
             "subtechniques": ["T1562.001 - Disable or Modify Tools", "T1562.004 - Disable or Modify System Firewall"]},
        ],
    },
    "Credential Access": {
        "id": "TA0006",
        "techniques": [
            {"id": "T1110", "name": "Brute Force",
             "subtechniques": ["T1110.001 - Password Guessing", "T1110.003 - Password Spraying", "T1110.004 - Credential Stuffing"]},
            {"id": "T1003", "name": "OS Credential Dumping",
             "subtechniques": ["T1003.001 - LSASS Memory", "T1003.002 - SAM", "T1003.003 - NTDS"]},
            {"id": "T1555", "name": "Credentials from Password Stores"},
            {"id": "T1539", "name": "Steal Web Session Cookie"},
            {"id": "T1528", "name": "Steal Application Access Token"},
        ],
    },
    "Discovery": {
        "id": "TA0007",
        "techniques": [
            {"id": "T1083", "name": "File and Directory Discovery"},
            {"id": "T1057", "name": "Process Discovery"},
            {"id": "T1018", "name": "Remote System Discovery"},
            {"id": "T1082", "name": "System Information Discovery"},
            {"id": "T1016", "name": "System Network Configuration Discovery"},
            {"id": "T1087", "name": "Account Discovery"},
        ],
    },
    "Lateral Movement": {
        "id": "TA0008",
        "techniques": [
            {"id": "T1021", "name": "Remote Services",
             "subtechniques": ["T1021.001 - Remote Desktop Protocol", "T1021.002 - SMB/Windows Admin Shares", "T1021.004 - SSH"]},
            {"id": "T1210", "name": "Exploitation of Remote Services"},
            {"id": "T1534", "name": "Internal Spearphishing"},
            {"id": "T1550", "name": "Use Alternate Authentication Material",
             "subtechniques": ["T1550.002 - Pass the Hash", "T1550.003 - Pass the Ticket"]},
        ],
    },
    "Collection": {
        "id": "TA0009",
        "techniques": [
            {"id": "T1005", "name": "Data from Local System"},
            {"id": "T1114", "name": "Email Collection"},
            {"id": "T1119", "name": "Automated Collection"},
            {"id": "T1074", "name": "Data Staged"},
            {"id": "T1123", "name": "Audio Capture"},
            {"id": "T1056", "name": "Input Capture",
             "subtechniques": ["T1056.001 - Keylogging"]},
        ],
    },
    "Command and Control": {
        "id": "TA0011",
        "techniques": [
            {"id": "T1071", "name": "Application Layer Protocol",
             "subtechniques": ["T1071.001 - Web Protocols", "T1071.004 - DNS"]},
            {"id": "T1573", "name": "Encrypted Channel",
             "subtechniques": ["T1573.001 - Symmetric Cryptography", "T1573.002 - Asymmetric Cryptography"]},
            {"id": "T1105", "name": "Ingress Tool Transfer"},
            {"id": "T1090", "name": "Proxy",
             "subtechniques": ["T1090.003 - Multi-hop Proxy"]},
            {"id": "T1102", "name": "Web Service"},
        ],
    },
    "Exfiltration": {
        "id": "TA0010",
        "techniques": [
            {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol",
             "subtechniques": ["T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol"]},
            {"id": "T1567", "name": "Exfiltration Over Web Service",
             "subtechniques": ["T1567.002 - Exfiltration to Cloud Storage"]},
            {"id": "T1029", "name": "Scheduled Transfer"},
            {"id": "T1030", "name": "Data Transfer Size Limits"},
        ],
    },
    "Impact": {
        "id": "TA0040",
        "techniques": [
            {"id": "T1486", "name": "Data Encrypted for Impact"},
            {"id": "T1489", "name": "Service Stop"},
            {"id": "T1490", "name": "Inhibit System Recovery"},
            {"id": "T1498", "name": "Network Denial of Service",
             "subtechniques": ["T1498.001 - Direct Network Flood", "T1498.002 - Reflection Amplification"]},
            {"id": "T1485", "name": "Data Destruction"},
            {"id": "T1491", "name": "Defacement"},
            {"id": "T1496", "name": "Resource Hijacking"},
        ],
    },
}

KILL_CHAIN_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


# ─────────────────────────────────────────────
# Threat Actor Database (Known APT Groups)
# ─────────────────────────────────────────────

THREAT_ACTOR_DB = {
    "APT28": {
        "aliases": ["Fancy Bear", "Sofacy", "STRONTIUM", "Pawn Storm"],
        "nation_state": "Russia (GRU)",
        "active_since": 2007,
        "targets": ["Government", "Defense", "NATO", "Political Organizations"],
        "primary_tactics": ["Phishing", "Credential Access", "Lateral Movement"],
        "known_tools": ["X-Agent", "X-Tunnel", "Sofacy", "Zebrocy", "Drovorub"],
        "mitre_tactics": ["TA0001", "TA0006", "TA0008", "TA0011"],
        "threat_level": "CRITICAL",
    },
    "APT29": {
        "aliases": ["Cozy Bear", "YTTRIUM", "The Dukes", "NOBELIUM"],
        "nation_state": "Russia (SVR)",
        "active_since": 2008,
        "targets": ["Government", "Think Tanks", "Healthcare", "Energy"],
        "primary_tactics": ["Spearphishing", "Supply Chain", "Zero-Day Exploitation"],
        "known_tools": ["WellMess", "MiniDuke", "CozyDuke", "SUNBURST"],
        "mitre_tactics": ["TA0001", "TA0003", "TA0005", "TA0011"],
        "threat_level": "CRITICAL",
    },
    "Lazarus Group": {
        "aliases": ["HIDDEN COBRA", "Guardians of Peace", "APT38", "ZINC"],
        "nation_state": "North Korea (RGB)",
        "active_since": 2009,
        "targets": ["Financial", "Cryptocurrency", "Defense", "Media"],
        "primary_tactics": ["Spearphishing", "Watering Hole", "Supply Chain Attack"],
        "known_tools": ["RATANKBA", "Manuscrypt", "HOPLIGHT", "AppleJeus"],
        "mitre_tactics": ["TA0001", "TA0006", "TA0009", "TA0040"],
        "threat_level": "HIGH",
    },
    "APT41": {
        "aliases": ["WINNTI", "Double Dragon", "Barium", "Wicked Panda"],
        "nation_state": "China (MSS)",
        "active_since": 2012,
        "targets": ["Healthcare", "Telecom", "Technology", "Gaming"],
        "primary_tactics": ["Supply Chain Attack", "Zero-Day", "Ransomware", "Espionage"],
        "known_tools": ["MESSAGETAP", "PlugX", "ShadowPad", "Winnti"],
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0040"],
        "threat_level": "CRITICAL",
    },
    "Sandworm": {
        "aliases": ["BlackEnergy", "Voodoo Bear", "TEMP.Noble", "ELECTRUM"],
        "nation_state": "Russia (GRU Unit 74455)",
        "active_since": 2009,
        "targets": ["Critical Infrastructure", "Energy", "Government", "Military"],
        "primary_tactics": ["Destructive Malware", "ICS Attack", "Supply Chain"],
        "known_tools": ["BlackEnergy", "Industroyer", "NotPetya", "Cyclops Blink"],
        "mitre_tactics": ["TA0001", "TA0040", "TA0011"],
        "threat_level": "CRITICAL",
    },
    "FIN7": {
        "aliases": ["Carbanak", "Navigator Group", "ELBRUS"],
        "nation_state": "Cybercriminal (Ukraine/Russia)",
        "active_since": 2015,
        "targets": ["Retail", "Restaurant", "Hospitality", "Financial"],
        "primary_tactics": ["Spearphishing", "POS Malware", "Ransomware", "BEC"],
        "known_tools": ["Carbanak", "GRIFFON", "BOOSTWRITE", "CLAPS"],
        "mitre_tactics": ["TA0001", "TA0006", "TA0009", "TA0040"],
        "threat_level": "HIGH",
    },
    "Kimsuky": {
        "aliases": ["Black Banshee", "Velvet Chollima", "Thallium"],
        "nation_state": "North Korea (RGB)",
        "active_since": 2012,
        "targets": ["Government", "Think Tanks", "Nuclear Research", "South Korea"],
        "primary_tactics": ["Spearphishing", "Social Engineering", "Credential Harvesting"],
        "known_tools": ["BabyShark", "AppleSeed", "XRAT"],
        "mitre_tactics": ["TA0001", "TA0006", "TA0009"],
        "threat_level": "HIGH",
    },
}


class MITREMapper:
    """Maps detected threats to MITRE ATT&CK Tactics, Techniques, and Sub-techniques."""

    KEYWORD_MAP = {
        # Reconnaissance
        "scan": ("Reconnaissance", "T1595", "Active Scanning"),
        "port scan": ("Reconnaissance", "T1595", "Active Scanning"),
        "vulnerability scan": ("Reconnaissance", "T1595", "Active Scanning"),
        "osint": ("Reconnaissance", "T1592", "Gather Victim Host Information"),
        "enumeration": ("Reconnaissance", "T1590", "Gather Victim Network Information"),
        # Initial Access
        "phishing": ("Initial Access", "T1566", "Phishing"),
        "spearphishing": ("Initial Access", "T1566", "Phishing"),
        "exploit": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
        "exploit public": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
        "drive-by": ("Initial Access", "T1189", "Drive-by Compromise"),
        "valid account": ("Initial Access", "T1078", "Valid Accounts"),
        "default credential": ("Initial Access", "T1078", "Valid Accounts"),
        # Execution
        "rce": ("Execution", "T1203", "Exploitation for Client Execution"),
        "remote code execution": ("Execution", "T1203", "Exploitation for Client Execution"),
        "command injection": ("Execution", "T1059", "Command and Scripting Interpreter"),
        "powershell": ("Execution", "T1059", "Command and Scripting Interpreter"),
        "script": ("Execution", "T1059", "Command and Scripting Interpreter"),
        "sql injection": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
        "cross-site scripting": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
        # Persistence
        "webshell": ("Persistence", "T1505", "Server Software Component"),
        "web shell": ("Persistence", "T1505", "Server Software Component"),
        "backdoor": ("Persistence", "T1543", "Create or Modify System Process"),
        "cron": ("Persistence", "T1053", "Scheduled Task/Job"),
        "scheduled task": ("Persistence", "T1053", "Scheduled Task/Job"),
        # Privilege Escalation
        "privilege escalation": ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
        "uac bypass": ("Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism"),
        "token": ("Privilege Escalation", "T1134", "Access Token Manipulation"),
        # Credential Access
        "brute force": ("Credential Access", "T1110", "Brute Force"),
        "credential stuffing": ("Credential Access", "T1110", "Brute Force"),
        "password spray": ("Credential Access", "T1110", "Brute Force"),
        "credential": ("Credential Access", "T1003", "OS Credential Dumping"),
        "lsass": ("Credential Access", "T1003", "OS Credential Dumping"),
        "cookie": ("Credential Access", "T1539", "Steal Web Session Cookie"),
        # Lateral Movement
        "lateral movement": ("Lateral Movement", "T1210", "Exploitation of Remote Services"),
        "rdp": ("Lateral Movement", "T1021", "Remote Services"),
        "smb": ("Lateral Movement", "T1021", "Remote Services"),
        "ssh": ("Lateral Movement", "T1021", "Remote Services"),
        "pass the hash": ("Lateral Movement", "T1550", "Use Alternate Authentication Material"),
        # C2 & Exfiltration
        "c2": ("Command and Control", "T1071", "Application Layer Protocol"),
        "beacon": ("Command and Control", "T1071", "Application Layer Protocol"),
        "dns tunnel": ("Command and Control", "T1071", "Application Layer Protocol"),
        "exfiltration": ("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
        "data theft": ("Collection", "T1005", "Data from Local System"),
        "keylog": ("Collection", "T1056", "Input Capture"),
        # Impact
        "ransomware": ("Impact", "T1486", "Data Encrypted for Impact"),
        "encrypt": ("Impact", "T1486", "Data Encrypted for Impact"),
        "ddos": ("Impact", "T1498", "Network Denial of Service"),
        "denial of service": ("Impact", "T1498", "Network Denial of Service"),
        "wipe": ("Impact", "T1485", "Data Destruction"),
        "defacement": ("Impact", "T1491", "Defacement"),
        # Defense Evasion
        "obfuscation": ("Defense Evasion", "T1027", "Obfuscated Files or Information"),
        "log clear": ("Defense Evasion", "T1070", "Indicator Removal"),
        "masquerade": ("Defense Evasion", "T1036", "Masquerading"),
    }

    @staticmethod
    def map_threat(threat_description: str, attack_type: str = "") -> Dict[str, Any]:
        """Map a threat to MITRE ATT&CK framework."""
        combined = f"{threat_description} {attack_type}".lower()

        matched_tactic = "Initial Access"
        matched_technique_id = "T1190"
        matched_technique_name = "Exploit Public-Facing Application"

        # Longer matches take priority
        for keyword, (tactic, tech_id, tech_name) in sorted(
            MITREMapper.KEYWORD_MAP.items(), key=lambda x: len(x[0]), reverse=True
        ):
            if keyword in combined:
                matched_tactic = tactic
                matched_technique_id = tech_id
                matched_technique_name = tech_name
                break

        tactic_info = MITRE_ATTACK_MATRIX.get(matched_tactic, {})
        kill_chain_idx = KILL_CHAIN_ORDER.index(matched_tactic) if matched_tactic in KILL_CHAIN_ORDER else 0

        return {
            "tactic": matched_tactic,
            "tactic_id": tactic_info.get("id", ""),
            "technique_id": matched_technique_id,
            "technique_name": matched_technique_name,
            "kill_chain_phase": matched_tactic,
            "kill_chain_position": kill_chain_idx,
            "total_phases": len(KILL_CHAIN_ORDER),
            "attack_progress_pct": round((kill_chain_idx + 1) / len(KILL_CHAIN_ORDER) * 100, 1),
        }


class KillChainEngine:
    """Predictive Kill-Chain reconstruction and next-phase prediction engine."""

    @staticmethod
    def reconstruct_chain(current_phase: str, threat_data: Dict = None) -> Dict[str, Any]:
        """Reconstruct attack kill chain and predict next steps with probabilities."""
        try:
            current_idx = KILL_CHAIN_ORDER.index(current_phase)
        except ValueError:
            current_idx = 2  # Default to Initial Access

        completed_phases = KILL_CHAIN_ORDER[: current_idx + 1]

        predicted_next_phases = []
        for i, phase in enumerate(KILL_CHAIN_ORDER[current_idx + 1 :], 1):
            # Probability decreases with each step, with non-linear decay
            base_prob = 0.92 * (0.88 ** i)
            predicted_next_phases.append({
                "phase": phase,
                "probability": round(max(base_prob, 0.05), 3),
                "tactic_id": MITRE_ATTACK_MATRIX.get(phase, {}).get("id", ""),
                "likely_techniques": [
                    t["name"]
                    for t in MITRE_ATTACK_MATRIX.get(phase, {}).get("techniques", [])[:3]
                ],
                "defensive_action": KillChainEngine._recommend_action(phase),
            })

        return {
            "current_phase": current_phase,
            "current_phase_index": current_idx,
            "total_phases": len(KILL_CHAIN_ORDER),
            "completed_phases": completed_phases,
            "predicted_next_phases": predicted_next_phases,
            "most_likely_next": predicted_next_phases[0] if predicted_next_phases else None,
            "recommended_action": KillChainEngine._recommend_action(current_phase),
            "attack_progression_pct": round((current_idx + 1) / len(KILL_CHAIN_ORDER) * 100, 1),
            "dwell_time_estimate_days": max(1, 14 - current_idx * 1),
        }

    @staticmethod
    def _recommend_action(phase: str) -> str:
        actions = {
            "Reconnaissance": "Deploy honeypots; block scanning IPs; enable geo-based rate limiting",
            "Resource Development": "Monitor certificate transparency logs; track newly registered domains",
            "Initial Access": "Patch public-facing apps; enforce MFA; update email security filters",
            "Execution": "Enable application allowlisting; deploy EDR; restrict script interpreters",
            "Persistence": "Audit scheduled tasks, services, and registry run keys; enable change monitoring",
            "Privilege Escalation": "Apply least privilege; patch local vulnerabilities; monitor sudo/UAC events",
            "Defense Evasion": "Enable enhanced logging; deploy canary files; monitor process injection",
            "Credential Access": "Deploy credential guard; enforce strong MFA; monitor auth failure spikes",
            "Discovery": "Monitor lateral LDAP/WMI queries; deploy deception assets",
            "Lateral Movement": "Micro-segment network; monitor RDP/SMB/SSH; enforce PAM solutions",
            "Collection": "Enable DLP; monitor unusual file access; encrypt data at rest",
            "Command and Control": "Block known C2 infra; deploy DNS sinkholes; inspect outbound TLS",
            "Exfiltration": "Monitor outbound data volumes; restrict cloud uploads; enforce DLP alerts",
            "Impact": "Test backups immediately; activate BCP; isolate affected systems",
        }
        return actions.get(phase, "Review and assess the situation immediately")


class ThreatDNAFingerprinter:
    """Generates behavioural fingerprints for zero-day attack pattern recognition."""

    KNOWN_PATTERNS = [
        ("APT28 / Fancy Bear", 0.28, ["PowerShell", "C2 Beacon", "Lateral Movement"]),
        ("Cobalt Strike Beacon", 0.22, ["Named Pipe", "Process Injection", "Reflective DLL"]),
        ("Emotet Loader", 0.18, ["Macro Execution", "SMTP Propagation", "Module Download"]),
        ("Conti Ransomware", 0.20, ["SMB Propagation", "Credential Dump", "Encryption"]),
        ("Novel/Unknown Pattern", 0.38, ["Unclassified"]),
        ("QBot / QakBot", 0.15, ["Email Thread Hijack", "Web Inject", "VNC"]),
    ]

    @staticmethod
    def generate_fingerprint(features: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a Threat DNA fingerprint from behavioural features."""
        feature_str = str(sorted(features.items()))
        full_hash = hashlib.sha256(feature_str.encode()).hexdigest()
        short_hash = full_hash[:16]

        # Deterministic similarity scoring based on feature hash
        hash_int = int(full_hash[:8], 16)

        similarities = []
        for pattern_name, base_sim, indicators in ThreatDNAFingerprinter.KNOWN_PATTERNS:
            # Deterministic variation from hash
            variation = ((hash_int >> len(pattern_name)) % 100 - 50) / 500
            sim = min(max(base_sim + variation, 0.05), 0.98)
            similarities.append({
                "pattern": pattern_name,
                "similarity": round(sim, 4),
                "behavioral_indicators": indicators,
            })

        similarities.sort(key=lambda x: x["similarity"], reverse=True)
        top_match = similarities[0]

        return {
            "fingerprint": short_hash,
            "full_hash": full_hash,
            "feature_count": len(features),
            "pattern_similarities": similarities[:5],
            "closest_match": top_match,
            "is_novel": top_match["similarity"] < 0.35,
            "novelty_score": round(1 - top_match["similarity"], 4),
            "threat_family": top_match["pattern"],
            "behavioral_indicators": top_match["behavioral_indicators"],
            "generated_at": datetime.utcnow().isoformat(),
        }


class IOCEnricher:
    """Cross-source IOC (Indicator of Compromise) enrichment with deterministic results."""

    # Deterministic threat tag assignment based on indicator hash
    TAG_POOLS = {
        "ip": ["c2-server", "scanner", "botnet-node", "tor-exit", "vpn-node", "proxy", "brute-forcer", "malware-distributor"],
        "domain": ["phishing", "malware-hosting", "c2-domain", "typosquat", "newly-registered", "dga-domain", "parked"],
        "hash": ["ransomware", "trojan", "loader", "infostealer", "wiper", "backdoor", "dropper"],
        "url": ["phishing-page", "malware-download", "exploit-kit", "redirect-chain", "credential-harvest"],
    }

    THREAT_ACTORS = list(THREAT_ACTOR_DB.keys()) + ["Unknown Actor", "Cybercriminal Group"]

    GEOIP_TABLE = {
        # Deterministic fake ASN/geo data by hash range
        "0": ("Russia", "Moscow", "AS197695 - reg.ru"),
        "1": ("China", "Beijing", "AS4134 - CHINANET"),
        "2": ("North Korea", "Pyongyang", "AS131279 - STAR-KP"),
        "3": ("Iran", "Tehran", "AS197207 - MCCI"),
        "4": ("United States", "New York", "AS14618 - AMAZON-AES"),
        "5": ("Germany", "Frankfurt", "AS3320 - DTAG"),
        "6": ("Netherlands", "Amsterdam", "AS60781 - LeaseWeb"),
        "7": ("Ukraine", "Kyiv", "AS13249 - IT Systems"),
        "8": ("Brazil", "São Paulo", "AS53006 - Algar Telecom"),
        "9": ("India", "Mumbai", "AS45609 - Bharti Airtel"),
    }

    @staticmethod
    def enrich_ioc(indicator: str, indicator_type: str, osint_data: Dict = None) -> Dict[str, Any]:
        """Enrich an IOC with cross-reference data. Deterministic per indicator."""
        # Seed from indicator hash for reproducibility
        h = hashlib.sha256(indicator.encode()).hexdigest()
        hash_int = int(h[:8], 16)

        ioc_type = indicator_type.lower()
        tag_pool = IOCEnricher.TAG_POOLS.get(ioc_type, IOCEnricher.TAG_POOLS["domain"])
        tag_count = 2 + (hash_int % 3)
        selected_tags = []
        for i in range(tag_count):
            selected_tags.append(tag_pool[(hash_int + i * 7) % len(tag_pool)])

        actor_count = hash_int % 2
        actors = []
        for i in range(actor_count + 1):
            actors.append(IOCEnricher.THREAT_ACTORS[(hash_int + i * 13) % len(IOCEnricher.THREAT_ACTORS)])

        confidence = 0.50 + (hash_int % 50) / 100
        sources_count = 1 + (hash_int % 8)
        first_seen_days = 5 + (hash_int % 85)

        enriched: Dict[str, Any] = {
            "indicator": indicator,
            "type": indicator_type,
            "first_seen": (datetime.utcnow() - timedelta(days=first_seen_days)).isoformat(),
            "last_seen": datetime.utcnow().isoformat(),
            "sources_reporting": sources_count,
            "confidence": round(confidence, 2),
            "risk_score": min(int(confidence * 100 + sources_count * 5), 100),
            "tags": list(set(selected_tags)),
            "threat_actors": actors,
            "related_iocs": IOCEnricher._generate_related(indicator, hash_int),
            "enriched_at": datetime.utcnow().isoformat(),
        }

        if ioc_type == "ip":
            geo_key = str(hash_int % 10)
            geo = IOCEnricher.GEOIP_TABLE.get(geo_key, IOCEnricher.GEOIP_TABLE["0"])
            enriched["geolocation"] = {
                "country": geo[0],
                "city": geo[1],
                "asn": geo[2],
            }
            # Validate IP format
            try:
                ipaddress.ip_address(indicator)
                enriched["is_valid_ip"] = True
                enriched["ip_type"] = "public" if not ipaddress.ip_address(indicator).is_private else "private"
            except ValueError:
                enriched["is_valid_ip"] = False

        return enriched

    @staticmethod
    def _generate_related(indicator: str, hash_int: int) -> List[Dict]:
        related = []
        count = 1 + (hash_int % 3)
        ioc_types = ["ip", "domain", "hash", "url"]
        relationships = ["communicates-with", "resolves-to", "drops", "hosts", "related-to"]
        for i in range(count):
            related.append({
                "type": ioc_types[(hash_int + i) % len(ioc_types)],
                "value": f"ioc-{(hash_int + i * 17) % 99999:05d}.example.net",
                "relationship": relationships[(hash_int + i * 3) % len(relationships)],
            })
        return related
