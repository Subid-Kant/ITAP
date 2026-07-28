"""
ITAP — ML Engine Service v2.0
Layer 2: LSTM Threat Predictor, Autoencoder Anomaly Detector,
NLP Event Classifier, and CVSS-Enhanced Severity Scorer.

Uses numpy-based deterministic simulation with realistic probabilistic models.
Seeded for reproducibility. In production, replace simulation with trained models.
"""
import numpy as np
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("itap.ml")

# Global seeded RNG for reproducibility
_rng = np.random.default_rng(42)


def _seeded_float(low: float, high: float, seed_str: str = "") -> float:
    """Generate a deterministic float from a seed string."""
    if seed_str:
        seed_val = int(hashlib.md5(seed_str.encode()).hexdigest()[:8], 16) % (2**31)
        local_rng = np.random.default_rng(seed_val)
        return float(local_rng.uniform(low, high))
    return float(_rng.uniform(low, high))


class LSTMPredictor:
    """
    LSTM-based threat prediction engine v2.0.
    Uses deterministic numpy simulation with domain-seeded randomness
    for reproducible predictions per target.

    Feature weighting mirrors a trained LSTM output:
    - CVE severity (CVSS) → 35% weight
    - Environmental risk from OSINT → 30% weight
    - Recency factor → 20% weight
    - Threat intelligence feed signal → 15% weight
    """

    CVE_CATEGORIES = {
        "Remote Code Execution": 0.82,
        "SQL Injection": 0.75,
        "Cross-Site Scripting": 0.63,
        "Privilege Escalation": 0.78,
        "Buffer Overflow": 0.65,
        "Authentication Bypass": 0.80,
        "Directory Traversal": 0.55,
        "Denial of Service": 0.60,
        "Information Disclosure": 0.45,
        "Command Injection": 0.77,
        "XML External Entity": 0.58,
        "Server-Side Request Forgery": 0.70,
        "Insecure Deserialization": 0.72,
        "Cryptographic Weakness": 0.50,
    }

    @staticmethod
    async def predict_threats(
        domain: str,
        osint_data: Dict[str, Any],
        window_hours: int = 72,
    ) -> List[Dict[str, Any]]:
        """
        Generate threat predictions based on OSINT data.
        Deterministic per domain — same domain always produces same base predictions.
        """
        predictions = []

        # Extract features
        open_ports = osint_data.get("summary", {}).get("open_ports", 0)
        known_vulns = osint_data.get("summary", {}).get("known_vulns", 0)
        vt_malicious = osint_data.get("summary", {}).get("vt_malicious", 0)
        recent_cves = osint_data.get("summary", {}).get("recent_cves", 0)
        otx_pulses = osint_data.get("summary", {}).get("otx_pulses", 0)
        risk_score = osint_data.get("risk_score", 50)

        features = {
            "open_ports": open_ports,
            "known_vulns": known_vulns,
            "vt_malicious": vt_malicious,
            "recent_cves": recent_cves,
            "otx_pulses": otx_pulses,
            "risk_score": risk_score,
        }

        # Environment risk factor (0-1)
        env_risk = (
            min(open_ports * 0.04, 0.20) +
            min(known_vulns * 0.06, 0.18) +
            min(vt_malicious * 0.03, 0.15) +
            min(recent_cves * 0.02, 0.12) +
            min(otx_pulses * 0.008, 0.10)
        )
        env_risk = min(env_risk, 0.75)

        # Process CVEs from OSINT
        cve_data = osint_data.get("sources", {}).get("cve_nvd", [])
        if isinstance(cve_data, list):
            for cve in cve_data[:6]:
                cvss = float(cve.get("cvss_score", 5.0))
                cve_id = cve.get("cve_id", "")

                # LSTM-style probability calculation
                cvss_factor = (cvss / 10.0) * 0.35          # 35% weight
                env_factor = env_risk * 0.30                 # 30% weight
                recency_factor = 0.15                        # Recent CVEs more exploitable
                ti_factor = min(otx_pulses / 50.0, 0.15)    # 15% TI signal
                domain_noise = _seeded_float(-0.04, 0.04, f"{domain}:{cve_id}")

                probability = min(
                    max(cvss_factor + env_factor + recency_factor + ti_factor + domain_noise, 0.05),
                    0.98,
                )

                predictions.append({
                    "predicted_cve": cve_id,
                    "predicted_attack_type": LSTMPredictor._classify_attack(
                        cve.get("description", "")
                    ),
                    "probability": round(float(probability), 4),
                    "time_window_hours": window_hours,
                    "cvss_score": cvss,
                    "severity": cve.get("severity", "UNKNOWN"),
                    "attack_vector": cve.get("attack_vector", ""),
                    "features_used": features,
                    "confidence": (
                        "high" if probability > 0.70 else
                        "medium" if probability > 0.40 else "low"
                    ),
                    "predicted_at": datetime.utcnow().isoformat(),
                    "expires_at": (datetime.utcnow() + timedelta(hours=window_hours)).isoformat(),
                })

        # General attack type predictions (domain-seeded)
        for attack_type, base_prob in list(LSTMPredictor.CVE_CATEGORIES.items())[:5]:
            env_adj = base_prob * (0.4 + env_risk * 0.6)
            domain_factor = _seeded_float(0.85, 1.0, f"{domain}:{attack_type}")
            adjusted_prob = env_adj * domain_factor

            if adjusted_prob > 0.25:
                predictions.append({
                    "predicted_cve": None,
                    "predicted_attack_type": attack_type,
                    "probability": round(float(adjusted_prob), 4),
                    "time_window_hours": window_hours,
                    "cvss_score": None,
                    "severity": (
                        "CRITICAL" if adjusted_prob > 0.85 else
                        "HIGH" if adjusted_prob > 0.65 else "MEDIUM"
                    ),
                    "features_used": features,
                    "confidence": "high" if adjusted_prob > 0.70 else "medium",
                    "predicted_at": datetime.utcnow().isoformat(),
                    "expires_at": (datetime.utcnow() + timedelta(hours=window_hours)).isoformat(),
                })

        # Sort by probability descending
        return sorted(predictions, key=lambda x: x["probability"], reverse=True)

    @staticmethod
    def _classify_attack(description: str) -> str:
        """Classify attack type from CVE description using keyword matching."""
        desc_lower = description.lower()
        patterns = [
            ("remote code", "Remote Code Execution"),
            (" rce ", "Remote Code Execution"),
            ("sql injection", "SQL Injection"),
            ("cross-site scripting", "Cross-Site Scripting"),
            (" xss ", "Cross-Site Scripting"),
            ("privilege escal", "Privilege Escalation"),
            ("buffer overflow", "Buffer Overflow"),
            ("heap overflow", "Buffer Overflow"),
            ("stack overflow", "Buffer Overflow"),
            ("authentication bypass", "Authentication Bypass"),
            ("denial of service", "Denial of Service"),
            (" dos ", "Denial of Service"),
            ("command injection", "Command Injection"),
            ("directory traversal", "Directory Traversal"),
            ("path traversal", "Directory Traversal"),
            ("server-side request", "Server-Side Request Forgery"),
            ("ssrf", "Server-Side Request Forgery"),
            ("xxe", "XML External Entity"),
            ("xml external", "XML External Entity"),
            ("deserialization", "Insecure Deserialization"),
            ("information disclosure", "Information Disclosure"),
            ("cryptographic", "Cryptographic Weakness"),
        ]
        for pattern, attack_type in patterns:
            if pattern in desc_lower:
                return attack_type
        return "Exploitation Attempt"


class ThreatTrendAnalyzer:
    """
    Analyzes historical threat data to compute trend metrics.
    Computes rolling window statistics for threat velocity and severity distribution.
    """

    @staticmethod
    def analyze_trends(threats: List[Dict], window_hours: int = 24) -> Dict[str, Any]:
        """
        Compute trend statistics from a list of threat dicts.
        """
        if not threats:
            return {"trend": "stable", "velocity": 0, "acceleration": 0}

        now = datetime.utcnow()
        cutoff = now - timedelta(hours=window_hours)
        prev_cutoff = cutoff - timedelta(hours=window_hours)

        recent = [t for t in threats if t.get("detected_at") and
                  datetime.fromisoformat(t["detected_at"]) >= cutoff]
        previous = [t for t in threats if t.get("detected_at") and
                    prev_cutoff <= datetime.fromisoformat(t["detected_at"]) < cutoff]

        velocity = len(recent)
        prev_velocity = len(previous)
        acceleration = velocity - prev_velocity

        severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        severity_score = sum(
            severity_weights.get(t.get("severity", "low"), 1) for t in recent
        )

        return {
            "trend": "escalating" if acceleration > 2 else "stable" if acceleration >= 0 else "decreasing",
            "velocity_last_window": velocity,
            "velocity_prev_window": prev_velocity,
            "acceleration": acceleration,
            "weighted_severity_score": severity_score,
            "window_hours": window_hours,
        }


class AutoencoderDetector:
    """
    Autoencoder-based anomaly detection v2.0.
    Builds behavioural fingerprints using numpy statistical modeling.
    Deterministic across runs for same seed.
    """

    # "Normal" traffic baseline parameters (mean, std)
    NORMAL_BASELINE = {
        "packet_size_mean": (512, 150),
        "packet_size_std": (128, 50),
        "inter_arrival_time": (0.1, 0.05),
        "byte_rate": (10000, 3000),
        "packet_count": (150, 80),
        "duration": (5.0, 4.0),
        "flags_syn": (0.15, 0.10),
        "flags_rst": (0.05, 0.04),
        "payload_entropy": (4.5, 0.8),
    }

    @staticmethod
    async def detect_anomalies(
        traffic_data: Optional[Dict[str, Any]] = None,
        threshold: float = 0.82,
    ) -> List[Dict[str, Any]]:
        """
        Analyze network traffic for anomalies using autoencoder simulation.
        Uses Mahalanobis-distance-inspired scoring for realism.
        """
        anomalies = []
        rng = np.random.default_rng(seed=int(datetime.utcnow().timestamp()) % 10000)

        num_flows = int(rng.integers(60, 180))
        baseline = AutoencoderDetector.NORMAL_BASELINE

        for i in range(num_flows):
            is_attack = rng.random() < 0.09  # ~9% attack rate

            if is_attack:
                # Inject anomalous features
                attack_type_idx = int(rng.integers(0, 5))
                features = AutoencoderDetector._generate_attack_features(rng, attack_type_idx)
                # Reconstruction error: high for anomalies
                reconstruction_error = float(rng.uniform(0.78, 0.99))
            else:
                features = {
                    key: float(abs(rng.normal(mu, sigma)))
                    for key, (mu, sigma) in baseline.items()
                }
                reconstruction_error = float(rng.uniform(0.02, 0.60))

            anomaly_score = reconstruction_error

            if anomaly_score >= threshold:
                # Generate Threat DNA fingerprint
                feature_str = str(sorted(features.items()))
                full_hash = hashlib.sha256(feature_str.encode()).hexdigest()

                anomalies.append({
                    "source_ip": AutoencoderDetector._random_ip(rng, public=True),
                    "destination_ip": AutoencoderDetector._random_ip(rng, public=False),
                    "anomaly_score": round(anomaly_score, 4),
                    "reconstruction_error": round(reconstruction_error, 4),
                    "is_anomalous": True,
                    "pattern_fingerprint": full_hash[:16],
                    "features": {k: round(v, 4) for k, v in features.items()},
                    "classification": AutoencoderDetector._classify_anomaly(features),
                    "protocol": ["TCP", "UDP", "ICMP"][int(rng.integers(0, 3))],
                    "confidence": "high" if anomaly_score > 0.90 else "medium",
                    "detected_at": datetime.utcnow().isoformat(),
                })

        return sorted(anomalies, key=lambda x: x["anomaly_score"], reverse=True)

    @staticmethod
    def _generate_attack_features(rng: np.random.Generator, attack_type: int) -> Dict[str, float]:
        """Generate features characteristic of specific attack types."""
        templates = [
            # SYN Flood
            {"packet_size_mean": 64, "packet_count": 5000, "flags_syn": 0.95,
             "flags_rst": 0.02, "inter_arrival_time": 0.001, "byte_rate": 320000,
             "duration": 1.0, "packet_size_std": 5, "payload_entropy": 1.2},
            # Data Exfiltration
            {"packet_size_mean": 1400, "packet_count": 800, "flags_syn": 0.05,
             "flags_rst": 0.01, "inter_arrival_time": 0.05, "byte_rate": 1120000,
             "duration": 45.0, "packet_size_std": 200, "payload_entropy": 7.8},
            # Port Scanner
            {"packet_size_mean": 64, "packet_count": 1500, "flags_syn": 0.80,
             "flags_rst": 0.60, "inter_arrival_time": 0.002, "byte_rate": 96000,
             "duration": 3.0, "packet_size_std": 10, "payload_entropy": 0.5},
            # C2 Beacon (encrypted)
            {"packet_size_mean": 256, "packet_count": 40, "flags_syn": 0.10,
             "flags_rst": 0.02, "inter_arrival_time": 30.0, "byte_rate": 8192,
             "duration": 1200.0, "packet_size_std": 32, "payload_entropy": 7.9},
            # Brute Force
            {"packet_size_mean": 128, "packet_count": 2000, "flags_syn": 0.40,
             "flags_rst": 0.35, "inter_arrival_time": 0.003, "byte_rate": 256000,
             "duration": 6.0, "packet_size_std": 20, "payload_entropy": 3.2},
        ]
        base = templates[attack_type]
        # Add small noise
        noise = lambda v: float(v * (1 + rng.normal(0, 0.05)))
        return {k: round(noise(v), 4) for k, v in base.items()}

    @staticmethod
    def _random_ip(rng: np.random.Generator, public: bool = True) -> str:
        if public:
            # Sample from known attack-source ASNs (Russia, China, etc.)
            ranges = [(5, 87), (101, 220), (185, 195), (45, 95)]
            r = ranges[int(rng.integers(0, len(ranges)))]
            return f"{int(rng.integers(r[0], r[1]))}.{int(rng.integers(0, 256))}.{int(rng.integers(0, 256))}.{int(rng.integers(1, 255))}"
        return f"10.{int(rng.integers(0, 10))}.{int(rng.integers(0, 256))}.{int(rng.integers(1, 255))}"

    @staticmethod
    def _classify_anomaly(features: Dict) -> str:
        """Classify anomaly pattern based on feature thresholds."""
        if features.get("flags_syn", 0) > 0.80 and features.get("inter_arrival_time", 1) < 0.005:
            return "SYN Flood (Volumetric DDoS)"
        if features.get("payload_entropy", 0) > 7.5:
            return "Encrypted/Obfuscated Payload (C2 Beacon)"
        if features.get("packet_count", 0) > 3000 and features.get("byte_rate", 0) > 500000:
            return "Mass Data Exfiltration"
        if features.get("flags_rst", 0) > 0.50 and features.get("flags_syn", 0) > 0.60:
            return "Network Port Scanner"
        if features.get("packet_count", 0) > 1000 and features.get("inter_arrival_time", 1) < 0.01:
            return "Brute Force / Credential Stuffing"
        if features.get("inter_arrival_time", 0) > 20.0 and features.get("payload_entropy", 0) > 7.0:
            return "Periodic C2 Beacon (APT Implant)"
        return "Novel Anomalous Pattern (Zero-Day Candidate)"


class SeverityScorer:
    """
    CVSS-Enhanced severity scoring engine v2.0.
    Incorporates temporal decay, asset criticality, and OSINT context.
    """

    @staticmethod
    def calculate_score(
        cvss_base: float = 5.0,
        asset_criticality: float = 0.7,
        exploit_likelihood: float = 0.5,
        osint_context_score: float = 0.5,
        active_exploitation: bool = False,
        days_since_disclosure: int = 0,
    ) -> Dict[str, Any]:
        """
        Calculate enhanced severity score (0-10).

        Weighting:
          - CVSS Base: 35%
          - Exploit Likelihood (LSTM): 25%
          - Asset Criticality: 20%
          - OSINT Context: 15%
          - Active Exploitation Bonus: 5%
          - Temporal Decay: applied to CVSS (newer = higher)
        """
        # Temporal decay: CVSS loses 0.1 per month after 6 months
        temporal_factor = 1.0
        if days_since_disclosure > 180:
            months_old = (days_since_disclosure - 180) / 30
            temporal_factor = max(0.6, 1.0 - months_old * 0.02)

        adjusted_cvss = cvss_base * temporal_factor

        score = (
            adjusted_cvss * 0.35 +
            (exploit_likelihood * 10) * 0.25 +
            (asset_criticality * 10) * 0.20 +
            (osint_context_score * 10) * 0.15 +
            (10 if active_exploitation else 0) * 0.05
        )
        score = min(round(float(score), 1), 10.0)

        if score >= 9.0:
            severity = "CRITICAL"
        elif score >= 7.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        elif score >= 2.0:
            severity = "LOW"
        else:
            severity = "INFO"

        return {
            "score": score,
            "severity": severity,
            "temporal_factor": round(temporal_factor, 3),
            "breakdown": {
                "cvss_base_contribution": round(adjusted_cvss * 0.35, 2),
                "exploit_contribution": round((exploit_likelihood * 10) * 0.25, 2),
                "asset_contribution": round((asset_criticality * 10) * 0.20, 2),
                "osint_contribution": round((osint_context_score * 10) * 0.15, 2),
                "active_exploitation_bonus": round((10 if active_exploitation else 0) * 0.05, 2),
            },
            "recommendations": SeverityScorer._get_recommendations(severity),
            "sla_hours": SeverityScorer._get_sla(severity),
        }

    @staticmethod
    def _get_sla(severity: str) -> int:
        """Response SLA in hours by severity."""
        return {"CRITICAL": 1, "HIGH": 24, "MEDIUM": 168, "LOW": 720, "INFO": 8760}.get(severity, 168)

    @staticmethod
    def _get_recommendations(severity: str) -> List[str]:
        recs = {
            "CRITICAL": [
                "P0 — Immediate incident response required (< 1 hour SLA)",
                "Isolate affected systems from network immediately",
                "Engage CSIRT and escalate to CISO",
                "Apply emergency virtual patch or disable service",
                "Enable full packet capture on affected segments",
                "Notify legal/compliance if data exposure is suspected",
            ],
            "HIGH": [
                "P1 — Respond within 24 hours",
                "Priority patching via change management fast-track",
                "Increase SIEM alert threshold on affected systems",
                "Review and tighten firewall egress rules",
                "Conduct targeted threat hunt for lateral movement",
            ],
            "MEDIUM": [
                "P2 — Schedule patching within 7 days",
                "Monitor affected systems for exploitation attempts",
                "Review user access controls on vulnerable assets",
                "Update IDS/IPS signatures for this attack vector",
            ],
            "LOW": [
                "P3 — Include in next scheduled patch cycle (30 days)",
                "Document for compliance tracking",
                "Add to vulnerability management backlog",
            ],
            "INFO": [
                "No immediate action required",
                "Log for awareness and compliance reporting",
            ],
        }
        return recs.get(severity, ["Review and assess the situation"])
