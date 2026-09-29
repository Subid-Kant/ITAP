"""
ITAP — Pydantic Schemas
Request/Response models for all API endpoints.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import re
from pydantic import BaseModel, Field, field_validator


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

class NmapScanType(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    AGGRESSIVE = "aggressive"
    CUSTOM = "custom"


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

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        # Strict validation: Must not contain spaces, paths, or schema (must be hostname or IP)
        if not re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$|^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$', v):
            raise ValueError("Must be a valid hostname or IPv4 address")
        return v


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
    nmap_enabled: bool = Field(default=False, description="Enable active Nmap scanning")
    nmap_scan_type: NmapScanType = Field(default=NmapScanType.STANDARD, description="Nmap scan type")
    nmap_custom_ports: Optional[str] = Field(default=None, description="e.g. '80,443,8000-8080'")

    @field_validator("nmap_custom_ports")
    @classmethod
    def validate_ports(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return v
        parts = v.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                try:
                    start, end = part.split('-')
                    start, end = int(start), int(end)
                    if not (1 <= start <= 65535 and 1 <= end <= 65535):
                        raise ValueError("Ports must be between 1 and 65535")
                    if start > end:
                        raise ValueError("Port range start must be <= end")
                except ValueError as e:
                    raise ValueError(f"Invalid port range '{part}': {e}")
            else:
                try:
                    p = int(part)
                    if not (1 <= p <= 65535):
                        raise ValueError("Ports must be between 1 and 65535")
                except ValueError:
                    raise ValueError(f"Invalid port '{part}'")
        return v


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

    # ── Root Cause & Remediation ─────────────────────────────
    root_cause: Optional[str] = None
    cve_description: Optional[str] = None
    affected_components: Optional[List[str]] = None
    attack_vector_detail: Optional[str] = None
    remediation: Optional[List[Dict[str, Any]]] = None

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
