"""
ITAP — Database Models
Defines all ORM models for threat intelligence storage, OSINT data, 
scan results, incidents, alerts, and playbooks.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, Integer, Boolean, Text, DateTime, JSON, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import relationship
from app.db.database import Base
import enum


class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


# ─────────────────────────────────────────────
# Layer 1 — OSINT Data Models
# ─────────────────────────────────────────────

class Target(Base):
    """Target domain/IP being monitored."""
    __tablename__ = "targets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    domain = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    organization = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    threats = relationship("Threat", back_populates="target", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    """OSINT scan results for a target."""
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    scan_type = Column(String(50), nullable=False)  # shodan, virustotal, censys, otx, cve
    status = Column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    results = Column(JSON, nullable=True)
    open_ports = Column(JSON, nullable=True)
    vulnerabilities = Column(JSON, nullable=True)
    reputation_score = Column(Float, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    target = relationship("Target", back_populates="scans")


class OSINTData(Base):
    """Raw OSINT data collected from various sources."""
    __tablename__ = "osint_data"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    source = Column(String(50), nullable=False, index=True)  # shodan, virustotal, etc.
    indicator_type = Column(String(50), nullable=False)  # ip, domain, hash, url
    indicator_value = Column(String(500), nullable=False, index=True)
    raw_data = Column(JSON, nullable=True)
    enrichment_data = Column(JSON, nullable=True)
    confidence_score = Column(Float, default=0.0)
    collected_at = Column(DateTime, default=datetime.utcnow)


# ─────────────────────────────────────────────
# Layer 2 — AI/ML Processing Models
# ─────────────────────────────────────────────

class ThreatPrediction(Base):
    """LSTM-based threat predictions."""
    __tablename__ = "threat_predictions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_domain = Column(String(255), nullable=False, index=True)
    predicted_cve = Column(String(50), nullable=True)
    predicted_attack_type = Column(String(100), nullable=True)
    probability = Column(Float, nullable=False)
    time_window_hours = Column(Integer, default=72)
    features_used = Column(JSON, nullable=True)
    model_version = Column(String(20), default="1.0")
    predicted_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)


class AnomalyDetection(Base):
    """Autoencoder anomaly detection results."""
    __tablename__ = "anomaly_detections"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    source_ip = Column(String(45), nullable=True)
    destination_ip = Column(String(45), nullable=True)
    anomaly_score = Column(Float, nullable=False)
    is_anomalous = Column(Boolean, default=False)
    features = Column(JSON, nullable=True)
    reconstruction_error = Column(Float, nullable=True)
    pattern_fingerprint = Column(String(128), nullable=True)  # "Threat DNA"
    detected_at = Column(DateTime, default=datetime.utcnow)


# ─────────────────────────────────────────────
# Layer 3 — Threat Intelligence Models
# ─────────────────────────────────────────────

class Threat(Base):
    """Detected threat with severity and MITRE ATT&CK mapping."""
    __tablename__ = "threats"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String, ForeignKey("targets.id"), nullable=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(SAEnum(SeverityLevel), default=SeverityLevel.MEDIUM)
    severity_score = Column(Float, default=5.0)
    category = Column(String(100), nullable=True)

    # MITRE ATT&CK Mapping
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique_id = Column(String(20), nullable=True)
    mitre_technique_name = Column(String(200), nullable=True)
    mitre_sub_technique = Column(String(200), nullable=True)
    kill_chain_phase = Column(String(100), nullable=True)
    predicted_next_step = Column(String(200), nullable=True)

    # IOC Data
    ioc_type = Column(String(50), nullable=True)
    ioc_value = Column(String(500), nullable=True)
    source_feeds = Column(JSON, nullable=True)
    
    # Geolocation
    source_country = Column(String(100), nullable=True)
    source_city = Column(String(100), nullable=True)
    source_latitude = Column(Float, nullable=True)
    source_longitude = Column(Float, nullable=True)

    is_resolved = Column(Boolean, default=False)
    detected_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

    target = relationship("Target", back_populates="threats")
    incidents = relationship("Incident", back_populates="threat")


# ─────────────────────────────────────────────
# Layer 4 — Incident Response Models
# ─────────────────────────────────────────────

class Incident(Base):
    """Incident with linked threat, playbook, and remediation tracking."""
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String, ForeignKey("targets.id"), nullable=True)
    threat_id = Column(String, ForeignKey("threats.id"), nullable=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(SAEnum(SeverityLevel), default=SeverityLevel.MEDIUM)
    status = Column(SAEnum(IncidentStatus), default=IncidentStatus.OPEN)

    # AI Playbook
    playbook_content = Column(Text, nullable=True)
    playbook_steps = Column(JSON, nullable=True)

    # Timeline
    detected_at = Column(DateTime, default=datetime.utcnow)
    acknowledged_at = Column(DateTime, nullable=True)
    contained_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)

    # Alerts
    alert_sent = Column(Boolean, default=False)
    alert_channels = Column(JSON, nullable=True)  # ["email", "webhook", "slack"]

    target = relationship("Target", back_populates="incidents")
    threat = relationship("Threat", back_populates="incidents")
    remediation_logs = relationship("RemediationLog", back_populates="incident", cascade="all, delete-orphan")


class RemediationLog(Base):
    """Audit trail for remediation actions."""
    __tablename__ = "remediation_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=False)
    action = Column(String(500), nullable=False)
    performed_by = Column(String(100), default="system")
    status = Column(String(50), default="completed")
    details = Column(Text, nullable=True)
    performed_at = Column(DateTime, default=datetime.utcnow)

    incident = relationship("Incident", back_populates="remediation_logs")


# ─────────────────────────────────────────────
# Dashboard / Reporting
# ─────────────────────────────────────────────

class DashboardMetric(Base):
    """Pre-computed dashboard metrics for fast loading."""
    __tablename__ = "dashboard_metrics"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    metric_name = Column(String(100), nullable=False, index=True)
    metric_value = Column(Float, nullable=False)
    metric_data = Column(JSON, nullable=True)
    period = Column(String(20), default="daily")  # hourly, daily, weekly
    computed_at = Column(DateTime, default=datetime.utcnow)
