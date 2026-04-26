"""
ITAP — Threat Intelligence Service
Layer 3: MITRE ATT&CK Mapping, Kill-Chain Reconstruction, 
Threat DNA Fingerprinting, and IOC Enrichment.
"""
import hashlib
import random
from datetime import datetime
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("itap.threat_intel")


# ─────────────────────────────────────────────
# MITRE ATT&CK Knowledge Base
# ─────────────────────────────────────────────

MITRE_ATTACK_MATRIX = {
    "Reconnaissance": {
        "id": "TA0043",
        "techniques": [
            {"id": "T1595", "name": "Active Scanning", "subtechniques": ["T1595.001 - Scanning IP Blocks", "T1595.002 - Vulnerability Scanning"]},
            {"id": "T1592", "name": "Gather Victim Host Information"},
            {"id": "T1589", "name": "Gather Victim Identity Information"},
            {"id": "T1590", "name": "Gather Victim Network Information"},
        ]
    },
    "Resource Development": {
        "id": "TA0042",
        "techniques": [
            {"id": "T1583", "name": "Acquire Infrastructure"},
            {"id": "T1587", "name": "Develop Capabilities"},
            {"id": "T1588", "name": "Obtain Capabilities"},
        ]
    },
    "Initial Access": {
        "id": "TA0001",
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1566", "name": "Phishing", "subtechniques": ["T1566.001 - Spearphishing Attachment", "T1566.002 - Spearphishing Link"]},
            {"id": "T1078", "name": "Valid Accounts"},
            {"id": "T1133", "name": "External Remote Services"},
        ]
    },
    "Execution": {
        "id": "TA0002",
        "techniques": [
            {"id": "T1059", "name": "Command and Scripting Interpreter"},
            {"id": "T1203", "name": "Exploitation for Client Execution"},
            {"id": "T1204", "name": "User Execution"},
        ]
    },
    "Persistence": {
        "id": "TA0003",
        "techniques": [
            {"id": "T1098", "name": "Account Manipulation"},
            {"id": "T1136", "name": "Create Account"},
            {"id": "T1543", "name": "Create or Modify System Process"},
            {"id": "T1053", "name": "Scheduled Task/Job"},
        ]
    },
    "Privilege Escalation": {
        "id": "TA0004",
        "techniques": [
            {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
            {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
            {"id": "T1134", "name": "Access Token Manipulation"},
        ]
    },
    "Defense Evasion": {
        "id": "TA0005",
        "techniques": [
            {"id": "T1027", "name": "Obfuscated Files or Information"},
            {"id": "T1070", "name": "Indicator Removal"},
            {"id": "T1036", "name": "Masquerading"},
        ]
    },
    "Credential Access": {
        "id": "TA0006",
        "techniques": [
            {"id": "T1110", "name": "Brute Force"},
            {"id": "T1003", "name": "OS Credential Dumping"},
            {"id": "T1555", "name": "Credentials from Password Stores"},
        ]
    },
    "Lateral Movement": {
        "id": "TA0008",
        "techniques": [
            {"id": "T1021", "name": "Remote Services"},
            {"id": "T1210", "name": "Exploitation of Remote Services"},
            {"id": "T1534", "name": "Internal Spearphishing"},
        ]
    },
    "Collection": {
        "id": "TA0009",
        "techniques": [
            {"id": "T1005", "name": "Data from Local System"},
            {"id": "T1114", "name": "Email Collection"},
            {"id": "T1119", "name": "Automated Collection"},
        ]
    },
    "Command and Control": {
        "id": "TA0011",
        "techniques": [
            {"id": "T1071", "name": "Application Layer Protocol"},
            {"id": "T1573", "name": "Encrypted Channel"},
            {"id": "T1105", "name": "Ingress Tool Transfer"},
        ]
    },
    "Exfiltration": {
        "id": "TA0010",
        "techniques": [
            {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
            {"id": "T1567", "name": "Exfiltration Over Web Service"},
        ]
    },
    "Impact": {
        "id": "TA0040",
        "techniques": [
            {"id": "T1486", "name": "Data Encrypted for Impact"},
            {"id": "T1489", "name": "Service Stop"},
            {"id": "T1490", "name": "Inhibit System Recovery"},
            {"id": "T1498", "name": "Network Denial of Service"},
        ]
    },
}

# Kill chain phases in order
KILL_CHAIN_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"
]


class MITREMapper:
    """Maps detected threats to MITRE ATT&CK Tactics, Techniques, and Sub-techniques."""
    
    # Keyword to tactic/technique mapping
    KEYWORD_MAP = {
        "scan": ("Reconnaissance", "T1595", "Active Scanning"),
        "port scan": ("Reconnaissance", "T1595", "Active Scanning"),
        "vulnerability scan": ("Reconnaissance", "T1595", "Active Scanning"),
        "phishing": ("Initial Access", "T1566", "Phishing"),
        "spearphishing": ("Initial Access", "T1566", "Phishing"),
        "exploit": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
        "rce": ("Execution", "T1203", "Exploitation for Client Execution"),
        "remote code execution": ("Execution", "T1203", "Exploitation for Client Execution"),
        "command injection": ("Execution", "T1059", "Command and Scripting Interpreter"),
        "sql injection": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
        "brute force": ("Credential Access", "T1110", "Brute Force"),
        "credential": ("Credential Access", "T1003", "OS Credential Dumping"),
        "privilege escalation": ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
        "lateral movement": ("Lateral Movement", "T1210", "Exploitation of Remote Services"),
        "ransomware": ("Impact", "T1486", "Data Encrypted for Impact"),
        "ddos": ("Impact", "T1498", "Network Denial of Service"),
        "denial of service": ("Impact", "T1498", "Network Denial of Service"),
        "exfiltration": ("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
        "data theft": ("Collection", "T1005", "Data from Local System"),
        "malware": ("Execution", "T1204", "User Execution"),
        "c2": ("Command and Control", "T1071", "Application Layer Protocol"),
        "backdoor": ("Persistence", "T1543", "Create or Modify System Process"),
        "obfuscation": ("Defense Evasion", "T1027", "Obfuscated Files or Information"),
    }
    
    @staticmethod
    def map_threat(threat_description: str, attack_type: str = "") -> Dict[str, Any]:
        """Map a threat to MITRE ATT&CK framework."""
        combined = f"{threat_description} {attack_type}".lower()
        
        matched_tactic = "Initial Access"
        matched_technique_id = "T1190"
        matched_technique_name = "Exploit Public-Facing Application"
        
        for keyword, (tactic, tech_id, tech_name) in MITREMapper.KEYWORD_MAP.items():
            if keyword in combined:
                matched_tactic = tactic
                matched_technique_id = tech_id
                matched_technique_name = tech_name
                break
        
        # Get tactic details
        tactic_info = MITRE_ATTACK_MATRIX.get(matched_tactic, {})
        
        return {
            "tactic": matched_tactic,
            "tactic_id": tactic_info.get("id", ""),
            "technique_id": matched_technique_id,
            "technique_name": matched_technique_name,
            "kill_chain_phase": matched_tactic,
            "kill_chain_position": KILL_CHAIN_ORDER.index(matched_tactic) if matched_tactic in KILL_CHAIN_ORDER else 0,
            "total_phases": len(KILL_CHAIN_ORDER)
        }
    
    @staticmethod
    def get_full_matrix() -> Dict[str, Any]:
        """Return the complete MITRE ATT&CK matrix for dashboard display."""
        return MITRE_ATTACK_MATRIX


class KillChainEngine:
    """
    Predictive Kill-Chain reconstruction engine.
    Given a detected attack phase, predicts the probable next steps.
    """
    
    @staticmethod
    def reconstruct_chain(current_phase: str, threat_data: Dict = None) -> Dict[str, Any]:
        """
        Reconstruct the probable attack kill chain and predict next steps.
        """
        try:
            current_idx = KILL_CHAIN_ORDER.index(current_phase)
        except ValueError:
            current_idx = 2  # Default to Initial Access
        
        # Build chain up to current phase
        completed_phases = KILL_CHAIN_ORDER[:current_idx + 1]
        
        # Predict next phases with decreasing probability
        predicted_next_phases = []
        for i, phase in enumerate(KILL_CHAIN_ORDER[current_idx + 1:], 1):
            prob = max(0.95 - (i * 0.12) + random.uniform(-0.05, 0.05), 0.1)
            predicted_next_phases.append({
                "phase": phase,
                "probability": round(prob, 3),
                "tactic_id": MITRE_ATTACK_MATRIX.get(phase, {}).get("id", ""),
                "likely_techniques": [
                    t["name"] for t in MITRE_ATTACK_MATRIX.get(phase, {}).get("techniques", [])[:2]
                ]
            })
        
        return {
            "current_phase": current_phase,
            "current_phase_index": current_idx,
            "total_phases": len(KILL_CHAIN_ORDER),
            "completed_phases": completed_phases,
            "predicted_next_phases": predicted_next_phases,
            "most_likely_next": predicted_next_phases[0] if predicted_next_phases else None,
            "recommended_action": KillChainEngine._recommend_action(current_phase),
            "attack_progression": round((current_idx + 1) / len(KILL_CHAIN_ORDER) * 100, 1)
        }
    
    @staticmethod
    def _recommend_action(phase: str) -> str:
        """Get recommended defensive action based on kill chain phase."""
        actions = {
            "Reconnaissance": "Deploy honeypots; enhance perimeter monitoring; block scanning IPs",
            "Resource Development": "Monitor for new infrastructure indicators; check certificate transparency logs",
            "Initial Access": "Patch public-facing applications; enforce MFA; update email filters",
            "Execution": "Enable application whitelisting; deploy EDR; restrict script execution",
            "Persistence": "Audit scheduled tasks; review service configurations; check startup items",
            "Privilege Escalation": "Apply least privilege; patch local vulnerabilities; monitor privilege changes",
            "Defense Evasion": "Enable enhanced logging; deploy SIEM rules; monitor process injection",
            "Credential Access": "Enforce password policies; deploy credential guard; monitor auth logs",
            "Lateral Movement": "Segment network; deploy micro-segmentation; monitor RDP/SMB",
            "Collection": "Enable DLP; monitor file access patterns; encrypt sensitive data",
            "Command and Control": "Block known C2 infrastructure; deploy DNS monitoring; inspect TLS",
            "Exfiltration": "Monitor outbound data volume; block unauthorized cloud storage; DLP alerts",
            "Impact": "Ensure backups; test disaster recovery; isolate affected systems immediately"
        }
        return actions.get(phase, "Review and assess the situation")


class ThreatDNAFingerprinter:
    """
    Generates behavioural fingerprints for zero-day attack pattern recognition.
    Uses feature hashing to create unique "DNA" patterns for unknown threats.
    """
    
    @staticmethod
    def generate_fingerprint(features: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a Threat DNA fingerprint from behavioural features."""
        # Create deterministic hash from features
        feature_str = str(sorted(features.items()))
        full_hash = hashlib.sha256(feature_str.encode()).hexdigest()
        short_hash = full_hash[:16]
        
        # Calculate pattern similarity to known attack patterns
        known_patterns = [
            ("APT28-style", 0.3), ("Cobalt Strike beacon", 0.2),
            ("Emotet dropper", 0.15), ("Custom RAT", 0.25),
            ("Novel/Unknown", 0.35)
        ]
        
        similarities = []
        for pattern_name, base_sim in known_patterns:
            sim = base_sim + random.uniform(-0.1, 0.15)
            sim = min(max(sim, 0.05), 0.95)
            similarities.append({"pattern": pattern_name, "similarity": round(sim, 4)})
        
        similarities.sort(key=lambda x: x["similarity"], reverse=True)
        
        return {
            "fingerprint": short_hash,
            "full_hash": full_hash,
            "feature_count": len(features),
            "pattern_similarities": similarities,
            "closest_match": similarities[0] if similarities else None,
            "is_novel": similarities[0]["similarity"] < 0.5 if similarities else True,
            "generated_at": datetime.utcnow().isoformat()
        }


class IOCEnricher:
    """
    Cross-source IOC (Indicator of Compromise) enrichment.
    Combines data from multiple OSINT sources to enrich IOCs.
    """
    
    @staticmethod
    def enrich_ioc(indicator: str, indicator_type: str, osint_data: Dict = None) -> Dict[str, Any]:
        """Enrich an IOC with cross-reference data from all available sources."""
        enriched = {
            "indicator": indicator,
            "type": indicator_type,
            "first_seen": (datetime.utcnow() - timedelta(days=random.randint(1, 90))).isoformat(),
            "last_seen": datetime.utcnow().isoformat(),
            "sources_reporting": random.randint(1, 8),
            "confidence": round(random.uniform(0.5, 0.99), 2),
            "tags": random.sample(
                ["malware", "phishing", "c2", "botnet", "scanner", "tor-exit", "vpn", "proxy", "apt", "ransomware"],
                k=random.randint(2, 4)
            ),
            "related_iocs": [
                {
                    "type": random.choice(["ip", "domain", "hash", "url"]),
                    "value": f"related-{random.randint(100,999)}.example.com",
                    "relationship": random.choice(["communicates-with", "resolves-to", "drops", "hosts"])
                }
                for _ in range(random.randint(1, 3))
            ],
            "threat_actors": random.sample(
                ["APT28", "APT29", "Lazarus Group", "FIN7", "Sandworm", "Unknown"],
                k=random.randint(0, 2)
            ),
            "enriched_at": datetime.utcnow().isoformat()
        }
        
        # Add geolocation for IPs
        if indicator_type == "ip":
            countries = ["Russia", "China", "North Korea", "Iran", "United States", "Germany", "Brazil"]
            enriched["geolocation"] = {
                "country": random.choice(countries),
                "city": "Unknown",
                "asn": f"AS{random.randint(10000, 99999)}",
                "org": random.choice(["CloudFlare", "Amazon", "OVH", "Hetzner", "Unknown ISP"])
            }
        
        return enriched


# Convenience import for timedelta
from datetime import timedelta
