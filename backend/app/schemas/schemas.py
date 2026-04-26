"""
ITAP — Pydantic Schemas
Request/Response models for all API endpoints.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ─── Enums ───
class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


# ─── Target ───
class TargetCreate(BaseModel):
    domain: str
    ip_address: Optional[str] = None
    organization: Optional[str] = None


class TargetResponse(BaseModel):
    id: str
    domain: str
    ip_address: Optional[str]
    organization: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ─── Scan ───
class ScanRequest(BaseModel):
    target_id: str
    scan_types: List[str] = Field(default=["shodan", "virustotal", "cve"])


class ScanResponse(BaseModel):
    id: str
    target_id: str
    scan_type: str
    status: str
    results: Optional[Dict[str, Any]]
    open_ports: Optional[List]
    vulnerabilities: Optional[List]
    reputation_score: Optional[float]
    started_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


# ─── Threat ───
class ThreatResponse(BaseModel):
    id: str
    title: str
    description: Optional[str]
    severity: str
    severity_score: float
    category: Optional[str]
    mitre_tactic: Optional[str]
    mitre_technique_id: Optional[str]
    mitre_technique_name: Optional[str]
    kill_chain_phase: Optional[str]
    predicted_next_step: Optional[str]
    ioc_type: Optional[str]
    ioc_value: Optional[str]
    source_country: Optional[str]
    source_latitude: Optional[float]
    source_longitude: Optional[float]
    is_resolved: bool
    detected_at: datetime

    class Config:
        from_attributes = True


# ─── Threat Prediction ───
class PredictionResponse(BaseModel):
    id: str
    target_domain: str
    predicted_cve: Optional[str]
    predicted_attack_type: Optional[str]
    probability: float
    time_window_hours: int
    predicted_at: datetime

    class Config:
        from_attributes = True


# ─── Anomaly ───
class AnomalyResponse(BaseModel):
    id: str
    source_ip: Optional[str]
    anomaly_score: float
    is_anomalous: bool
    pattern_fingerprint: Optional[str]
    detected_at: datetime

    class Config:
        from_attributes = True


# ─── Incident ───
class IncidentCreate(BaseModel):
    target_id: Optional[str] = None
    threat_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.MEDIUM


class IncidentResponse(BaseModel):
    id: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    playbook_content: Optional[str]
    playbook_steps: Optional[List]
    detected_at: datetime
    acknowledged_at: Optional[datetime]
    resolved_at: Optional[datetime]
    alert_sent: bool

    class Config:
        from_attributes = True


# ─── Dashboard ───
class DashboardStats(BaseModel):
    total_targets: int = 0
    active_threats: int = 0
    critical_threats: int = 0
    open_incidents: int = 0
    predictions_active: int = 0
    anomalies_detected: int = 0
    threats_by_severity: Dict[str, int] = {}
    threats_by_country: List[Dict[str, Any]] = []
    recent_threats: List[ThreatResponse] = []
    recent_incidents: List[IncidentResponse] = []
    threat_timeline: List[Dict[str, Any]] = []
    mitre_attack_coverage: List[Dict[str, Any]] = []


# ─── Playbook ───
class PlaybookRequest(BaseModel):
    incident_id: str
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    context: Optional[Dict[str, Any]] = None


class PlaybookResponse(BaseModel):
    incident_id: str
    playbook_content: str
    playbook_steps: List[Dict[str, str]]
    generated_at: datetime
