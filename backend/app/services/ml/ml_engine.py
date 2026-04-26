"""
ITAP — ML Engine Service
Layer 2: LSTM Threat Predictor, Autoencoder Anomaly Detector, 
NLP Event Classifier, and CVSS-Enhanced Severity Scorer.
"""
import numpy as np
import random
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import logging

logger = logging.getLogger("itap.ml")


class LSTMPredictor:
    """
    LSTM-based threat prediction engine.
    Uses historical breach datasets (NVD, CVE, Shodan feeds) to forecast 
    which vulnerabilities are likely to be exploited in the next 24-72 hours.
    
    In production, this would use a trained PyTorch LSTM model.
    For demo, it uses a sophisticated probabilistic simulation.
    """
    
    # Common CVE categories with base exploitation probability
    CVE_CATEGORIES = {
        "remote_code_execution": 0.82,
        "sql_injection": 0.75,
        "cross_site_scripting": 0.68,
        "privilege_escalation": 0.78,
        "buffer_overflow": 0.65,
        "authentication_bypass": 0.80,
        "directory_traversal": 0.55,
        "denial_of_service": 0.60,
        "information_disclosure": 0.45,
        "command_injection": 0.77,
    }
    
    @staticmethod
    async def predict_threats(
        domain: str, 
        osint_data: Dict[str, Any],
        window_hours: int = 72
    ) -> List[Dict[str, Any]]:
        """
        Generate threat predictions based on OSINT data and historical patterns.
        Returns predictions with probability scores.
        """
        predictions = []
        
        # Extract features from OSINT data
        open_ports = osint_data.get("summary", {}).get("open_ports", 0)
        known_vulns = osint_data.get("summary", {}).get("known_vulns", 0)
        vt_malicious = osint_data.get("summary", {}).get("vt_malicious", 0)
        recent_cves = osint_data.get("summary", {}).get("recent_cves", 0)
        risk_score = osint_data.get("risk_score", 50)
        
        # Feature vector for prediction
        features = {
            "open_ports": open_ports,
            "known_vulns": known_vulns,
            "vt_malicious": vt_malicious,
            "recent_cves": recent_cves,
            "risk_score": risk_score
        }
        
        # Generate predictions for each CVE category
        cve_data = osint_data.get("sources", {}).get("cve_nvd", [])
        if isinstance(cve_data, list):
            for cve in cve_data[:5]:
                cvss = cve.get("cvss_score", 5.0)
                # Simulate LSTM output: probability of exploitation
                base_prob = cvss / 10.0
                env_factor = (risk_score / 100.0) * 0.3
                recency = 0.15  # Recent CVEs more likely to be exploited
                noise = random.uniform(-0.05, 0.05)
                
                probability = min(max(base_prob * 0.55 + env_factor + recency + noise, 0.1), 0.98)
                
                predictions.append({
                    "predicted_cve": cve.get("cve_id"),
                    "predicted_attack_type": LSTMPredictor._classify_attack(cve.get("description", "")),
                    "probability": round(probability, 4),
                    "time_window_hours": window_hours,
                    "cvss_score": cvss,
                    "severity": cve.get("severity", "UNKNOWN"),
                    "features_used": features,
                    "confidence": "high" if probability > 0.7 else "medium" if probability > 0.4 else "low",
                    "predicted_at": datetime.utcnow().isoformat()
                })
        
        # Also predict general attack types
        for attack_type, base_prob in list(LSTMPredictor.CVE_CATEGORIES.items())[:3]:
            adjusted_prob = base_prob * (risk_score / 100) * random.uniform(0.6, 1.0)
            if adjusted_prob > 0.3:
                predictions.append({
                    "predicted_cve": None,
                    "predicted_attack_type": attack_type.replace("_", " ").title(),
                    "probability": round(adjusted_prob, 4),
                    "time_window_hours": window_hours,
                    "cvss_score": None,
                    "severity": "HIGH" if adjusted_prob > 0.7 else "MEDIUM",
                    "features_used": features,
                    "confidence": "high" if adjusted_prob > 0.7 else "medium",
                    "predicted_at": datetime.utcnow().isoformat()
                })
        
        return sorted(predictions, key=lambda x: x["probability"], reverse=True)
    
    @staticmethod
    def _classify_attack(description: str) -> str:
        """Classify attack type from CVE description."""
        desc_lower = description.lower()
        if "remote code" in desc_lower or "rce" in desc_lower:
            return "Remote Code Execution"
        elif "sql injection" in desc_lower:
            return "SQL Injection"
        elif "cross-site" in desc_lower or "xss" in desc_lower:
            return "Cross-Site Scripting"
        elif "privilege" in desc_lower or "escalation" in desc_lower:
            return "Privilege Escalation"
        elif "buffer overflow" in desc_lower:
            return "Buffer Overflow"
        elif "authentication" in desc_lower or "bypass" in desc_lower:
            return "Authentication Bypass"
        elif "denial" in desc_lower or "dos" in desc_lower:
            return "Denial of Service"
        else:
            return "Exploitation Attempt"


class AutoencoderDetector:
    """
    Autoencoder-based anomaly detection engine.
    Builds behavioural fingerprints of network traffic patterns.
    Detects zero-day attacks that don't match known signatures.
    """
    
    @staticmethod
    async def detect_anomalies(
        traffic_data: Optional[Dict[str, Any]] = None,
        threshold: float = 0.85
    ) -> List[Dict[str, Any]]:
        """
        Analyze traffic patterns for anomalies using autoencoder reconstruction error.
        In production, uses trained autoencoder model. Demo uses statistical simulation.
        """
        anomalies = []
        
        # Generate simulated network traffic analysis
        num_flows = random.randint(50, 200)
        
        for i in range(num_flows):
            # Simulate feature extraction from network flow
            features = {
                "packet_size_mean": random.gauss(512, 150),
                "packet_size_std": random.gauss(128, 50),
                "inter_arrival_time": random.expovariate(10),
                "byte_rate": random.gauss(10000, 3000),
                "packet_count": random.randint(10, 1000),
                "duration": random.uniform(0.1, 60),
                "protocol_id": random.choice([6, 17, 1]),  # TCP, UDP, ICMP
                "flags_syn": random.random(),
                "flags_rst": random.random() * 0.3,
                "payload_entropy": random.gauss(4.5, 1.2)
            }
            
            # Simulate reconstruction error (autoencoder output)
            # Normal traffic: low error. Anomalous: high error
            is_attack = random.random() < 0.08  # ~8% anomaly rate
            
            if is_attack:
                reconstruction_error = random.uniform(0.75, 0.99)
                # Generate "Threat DNA" fingerprint
                feature_str = str(sorted(features.items()))
                fingerprint = hashlib.sha256(feature_str.encode()).hexdigest()[:32]
            else:
                reconstruction_error = random.uniform(0.05, 0.65)
                fingerprint = None
            
            anomaly_score = reconstruction_error
            is_anomalous = anomaly_score >= threshold
            
            if is_anomalous:
                anomalies.append({
                    "source_ip": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}",
                    "destination_ip": f"10.0.{random.randint(0,255)}.{random.randint(1,255)}",
                    "anomaly_score": round(anomaly_score, 4),
                    "reconstruction_error": round(reconstruction_error, 4),
                    "is_anomalous": True,
                    "pattern_fingerprint": fingerprint,
                    "features": features,
                    "classification": AutoencoderDetector._classify_anomaly(features),
                    "detected_at": datetime.utcnow().isoformat()
                })
        
        return sorted(anomalies, key=lambda x: x["anomaly_score"], reverse=True)
    
    @staticmethod
    def _classify_anomaly(features: Dict) -> str:
        """Classify anomaly pattern type."""
        if features.get("flags_syn", 0) > 0.7:
            return "Potential SYN Flood"
        elif features.get("payload_entropy", 0) > 6:
            return "Encrypted/Obfuscated Payload (Possible C2)"
        elif features.get("packet_count", 0) > 800:
            return "Volume Anomaly (DDoS/Exfiltration)"
        elif features.get("inter_arrival_time", 0) < 0.01:
            return "Rapid Fire (Scanner/Brute Force)"
        else:
            return "Unknown Pattern (Zero-Day Candidate)"


class SeverityScorer:
    """
    Custom CVSS-Enhanced severity scoring engine.
    Weighs asset criticality + exploit likelihood + OSINT context
    to produce a unified severity score.
    """
    
    @staticmethod
    def calculate_score(
        cvss_base: float = 5.0,
        asset_criticality: float = 0.7,
        exploit_likelihood: float = 0.5,
        osint_context_score: float = 0.5,
        active_exploitation: bool = False
    ) -> Dict[str, Any]:
        """
        Calculate enhanced severity score.
        
        Returns:
            Dict with score (0-10), severity level, and breakdown.
        """
        # Weighted formula
        base_weight = 0.35
        asset_weight = 0.20
        exploit_weight = 0.25
        osint_weight = 0.15
        active_weight = 0.05
        
        score = (
            cvss_base * base_weight +
            (asset_criticality * 10) * asset_weight +
            (exploit_likelihood * 10) * exploit_weight +
            (osint_context_score * 10) * osint_weight +
            (10 if active_exploitation else 0) * active_weight
        )
        
        score = min(round(score, 1), 10.0)
        
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
            "breakdown": {
                "cvss_base_contribution": round(cvss_base * base_weight, 2),
                "asset_contribution": round((asset_criticality * 10) * asset_weight, 2),
                "exploit_contribution": round((exploit_likelihood * 10) * exploit_weight, 2),
                "osint_contribution": round((osint_context_score * 10) * osint_weight, 2),
                "active_exploitation_bonus": round((10 if active_exploitation else 0) * active_weight, 2)
            },
            "recommendations": SeverityScorer._get_recommendations(severity)
        }
    
    @staticmethod
    def _get_recommendations(severity: str) -> List[str]:
        """Get action recommendations based on severity."""
        recs = {
            "CRITICAL": [
                "Immediate incident response required",
                "Isolate affected systems",
                "Engage CSIRT/SOC team",
                "Apply emergency patches",
                "Enable enhanced monitoring"
            ],
            "HIGH": [
                "Priority patching within 24 hours",
                "Increase monitoring on affected assets",
                "Review and update firewall rules",
                "Conduct threat hunting"
            ],
            "MEDIUM": [
                "Schedule patching within 7 days",
                "Monitor for exploitation attempts",
                "Review access controls"
            ],
            "LOW": [
                "Schedule patching in next cycle",
                "Document for compliance tracking"
            ],
            "INFO": [
                "Log for awareness",
                "No immediate action required"
            ]
        }
        return recs.get(severity, ["Review and assess"])
