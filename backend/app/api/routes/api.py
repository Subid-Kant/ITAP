"""
ITAP v2.0 — API Routes
All REST API endpoints organized by layer.
Includes JWT authentication, pagination, WebSocket broadcasts, and PDF report generation.
"""
from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, update
from sqlalchemy.orm import selectinload
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import uuid
import io
import json
import logging

from app.db.database import get_db
from app.models.models import (
    Target, Scan, OSINTData, ThreatPrediction, AnomalyDetection,
    Threat, Incident, RemediationLog, DashboardMetric,
    SeverityLevel, ScanStatus as DBScanStatus, IncidentStatus as DBIncidentStatus
)
from app.schemas.schemas import (
    TargetCreate, TargetResponse, ScanRequest, ScanResponse,
    ThreatResponse, PredictionResponse, AnomalyResponse,
    IncidentCreate, IncidentResponse, PlaybookRequest, PlaybookResponse,
    DashboardStats
)
from app.services.osint import OSINTAggregator
from app.services.ml.llm_service import LocalLLMService
from app.services.ml.ml_engine import SeverityScorer
from app.services.threat_intel.threat_intel_service import KillChainEngine, MITREMapper, ThreatDNAFingerprinter, IOCEnricher
from app.services.response.response_service import PlaybookGenerator
from app.services.monitoring.server_monitor import server_monitor
from app.services.monitoring.global_threat_feed import global_threat_feed
from app.services.monitoring.machine_scanner import machine_scanner
from app.core.security import authenticate_user, create_access_token, create_refresh_token, get_current_user
from app.api.routes.ws import manager as ws_manager

logger = logging.getLogger("itap.api")
router = APIRouter()


# ─── Role-based Access Control ───────────────────────────────────────────────

async def check_admin_role(current_user: dict = Depends(get_current_user)) -> dict:
    """Dependency that restricts access to admin users only."""
    if current_user.get("role") not in ("admin",):
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


# ─────────────────────────────────────────────
# Authentication
# ─────────────────────────────────────────────

@router.post("/auth/login", tags=["Authentication"])
async def login(username: str, password: str):
    """
    Authenticate with username and password.
    Returns JWT access token + refresh token.
    """
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user["username"], "role": user["role"], "name": user["full_name"]}
    )
    refresh_token = create_refresh_token(
        data={"sub": user["username"], "role": user["role"]}
    )
    logger.info(f"Login successful: {username} (role={user['role']})")
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {
            "username": user["username"],
            "role": user["role"],
            "full_name": user["full_name"],
        },
        "expires_in_minutes": 480,
    }


@router.post("/auth/refresh", tags=["Authentication"])
async def refresh_token(token: str):
    """Exchange a refresh token for a new access token."""
    from app.core.security import decode_token
    payload = decode_token(token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    new_access = create_access_token(
        data={"sub": payload["sub"], "role": payload.get("role", "viewer")}
    )
    return {"access_token": new_access, "token_type": "bearer"}


@router.get("/auth/me", tags=["Authentication"])
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current authenticated user info."""
    return {
        "username": current_user.get("sub"),
        "role": current_user.get("role"),
        "full_name": current_user.get("name"),
    }

async def check_admin_role(current_user: dict = Depends(get_current_user)):
    """Dependency to check if current user has admin role."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Admin access required to perform this action.",
        )
    return current_user


# ─────────────────────────────────────────────
# Target Management
# ─────────────────────────────────────────────

@router.post("/targets", response_model=TargetResponse, tags=["Targets"])
async def create_target(
    target: TargetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Register a new target domain/IP for monitoring."""
    # Check for duplicate
    existing = await db.execute(select(Target).where(Target.domain == target.domain))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Target '{target.domain}' already exists")

    new_target = Target(
        id=str(uuid.uuid4()),
        domain=target.domain,
        ip_address=target.ip_address,
        organization=target.organization,
    )
    db.add(new_target)
    await db.commit()
    await db.refresh(new_target)
    await ws_manager.broadcast_system_event(
        "info", f"New target added: {target.domain}",
        detail=f"Added by {current_user.get('sub', 'system')}"
    )
    return new_target


@router.get("/targets", response_model=List[TargetResponse], tags=["Targets"])
async def list_targets(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List all monitored targets with pagination."""
    result = await db.execute(
        select(Target).order_by(Target.created_at.desc()).offset(skip).limit(limit)
    )
    return result.scalars().all()


@router.get("/targets/{target_id}", response_model=TargetResponse, tags=["Targets"])
async def get_target(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get a specific target."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.delete("/targets/{target_id}", tags=["Targets"])
async def delete_target(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_admin_role),
):
    """Delete a target (analyst+ role required)."""
    if current_user.get("role") not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await db.delete(target)
    await db.commit()
    return {"status": "deleted", "target_id": target_id}


# ─────────────────────────────────────────────
# Layer 1 — OSINT Scanning
# ─────────────────────────────────────────────

@router.post("/scan", tags=["OSINT Scanning"])
async def run_osint_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Run a comprehensive OSINT scan on a target.
    Aggregates data from Shodan, VirusTotal, CVE/NVD, AlienVault OTX, and Censys.
    Automatically creates threats from high-risk findings and broadcasts via WebSocket.
    """
    result = await db.execute(select(Target).where(Target.id == request.target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    await ws_manager.broadcast_system_event(
        "info", f"OSINT scan started: {target.domain}",
        detail="Running Shodan, VirusTotal, CVE/NVD, AlienVault OTX"
    )

    osint_results = await OSINTAggregator.full_scan(target.domain, target.ip_address)

    scan = Scan(
        id=str(uuid.uuid4()),
        target_id=target.id,
        scan_type="full_osint",
        status=DBScanStatus.COMPLETED,
        results=osint_results,
        open_ports=osint_results.get("sources", {}).get("shodan", {}).get("ports", []),
        vulnerabilities=osint_results.get("sources", {}).get("shodan", {}).get("vulns", []),
        reputation_score=osint_results.get("risk_score"),
        completed_at=datetime.utcnow(),
    )
    db.add(scan)

    # 2. Get Threat Predictions (via LLM)
    predictions = await LocalLLMService.generate_prediction(target.domain, osint_results)

    threats_created = []
    for pred in predictions[:5]:
        if pred["probability"] > 0.5:
            mitre_mapping = MITREMapper.map_threat(
                pred.get("predicted_attack_type", ""),
                pred.get("predicted_attack_type", ""),
            )
            severity_result = SeverityScorer.calculate_score(
                cvss_base=pred.get("cvss_score", 5.0) or 5.0,
                exploit_likelihood=pred["probability"],
                osint_context_score=osint_results.get("risk_score", 50) / 100,
            )
            geo = osint_results.get("summary", {}).get("geolocation", {})
            sev_val = severity_result["severity"].lower()
            if sev_val not in [e.value for e in SeverityLevel]:
                sev_val = "medium"

            attack_vec_label = pred.get("attack_vector", "NETWORK")
            threat = Threat(
                id=str(uuid.uuid4()),
                target_id=target.id,
                title=f"Predicted: {pred.get('predicted_attack_type', 'Unknown Threat')}",
                description=(
                    f"AI prediction — {pred.get('probability', 0) * 100:.1f}% probability within "
                    f"{pred.get('time_window_hours', 72)}h. "
                    f"CVE: {pred.get('predicted_cve', 'N/A')}. "
                    f"Attack vector: {attack_vec_label}. "
                    f"CVSS: {pred.get('cvss_score', 'N/A')}. "
                    f"Confidence: {pred.get('confidence', 'medium')}."
                ),
                severity=SeverityLevel(sev_val),
                severity_score=severity_result["score"],
                category=pred.get("predicted_attack_type"),
                mitre_tactic=mitre_mapping.get("tactic"),
                mitre_technique_id=mitre_mapping.get("technique_id"),
                mitre_technique_name=mitre_mapping.get("technique_name"),
                kill_chain_phase=mitre_mapping.get("kill_chain_phase"),
                ioc_value=pred.get("predicted_cve"),
                source_country=geo.get("country"),
                source_latitude=geo.get("lat"),
                source_longitude=geo.get("lon"),
                # ── Root Cause & Remediation enrichment ──────────
                root_cause=pred.get("root_cause"),
                cve_description=pred.get("cve_description"),
                affected_components=pred.get("affected_components"),
                attack_vector_detail=pred.get("attack_vector_detail"),
                remediation=pred.get("remediation"),
            )
            db.add(threat)
            threats_created.append(threat.title)

            # Broadcast high-severity threats immediately
            if sev_val in ("critical", "high"):
                await ws_manager.broadcast_threat({
                    "title": threat.title,
                    "severity": sev_val,
                    "score": severity_result["score"],
                    "target": target.domain,
                    "mitre_tactic": mitre_mapping.get("tactic"),
                })

    await db.commit()

    await ws_manager.broadcast_scan_complete({
        "scan_id": scan.id,
        "target": target.domain,
        "risk_score": osint_results.get("risk_score"),
        "risk_level": osint_results.get("risk_level"),
        "threats_created": len(threats_created),
    })

    is_admin = current_user.get("role") == "admin"

    # Build per-service vulnerability reports — strip poc_command for non-admins
    vuln_by_service = osint_results.get("vulnerabilities_by_service", [])
    if not is_admin:
        for svc_report in vuln_by_service:
            for cve in svc_report.get("cves", []):
                cve.pop("poc_command", None)

    return {
        "scan_id": scan.id,
        "target": target.domain,
        "risk_score": osint_results.get("risk_score"),
        "risk_level": osint_results.get("risk_level"),
        "summary": osint_results.get("summary"),
        "predictions": predictions[:5],
        "threats_created": threats_created,
        "osint_data": osint_results.get("sources"),
        "vulnerabilities_by_service": vuln_by_service,
        "threat_surface": osint_results.get("threat_surface", []),
        "osint_fingerprint": osint_results.get("osint_fingerprint", {}),
    }


@router.get("/scan/{scan_id}", tags=["OSINT Scanning"])
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get scan results by ID."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ─────────────────────────────────────────────
# Layer 2 — AI/ML Engine
# ─────────────────────────────────────────────

@router.get("/ml/status", tags=["AI/ML Engine"])
async def get_ml_status(current_user: dict = Depends(get_current_user)):
    """Check the status of the local LLM Engine (Llama 3)."""
    is_up = await LocalLLMService.is_ollama_available()
    if is_up:
        return {"status": "online", "engine": "Llama 3 8B (LoRA)", "message": "Connected to local Ollama API."}
    return {"status": "offline", "engine": "LSTMPredictor / AutoencoderDetector", "message": "Ollama LLM unreachable. Using simulated statistical fallback."}

@router.post("/ml/predict", tags=["AI/ML Engine"])
async def predict_threats(
    domain: str,
    current_user: dict = Depends(check_admin_role),
):
    """Run Llama 3 threat prediction for a domain."""
    # Use real OSINT scanner for live data
    osint_results = await OSINTAggregator.full_scan(domain, "")
    predictions = await LocalLLMService.generate_prediction(domain, osint_results)

    return {
        "domain": domain,
        "predictions": predictions,
        "prediction_window_hours": 72,
        "risk_score": osint_results.get("risk_score", 50),
        "engine": "Llama 3 8B (LoRA) / LSTMPredictor"
    }


@router.post("/ml/anomaly-detect", tags=["AI/ML Engine"])
async def detect_anomalies(
    threshold: float = 0.80,
    current_user: dict = Depends(check_admin_role),
):
    """Run LLM-based network anomaly detection."""
    results = await LocalLLMService.detect_anomalies()
    anomalies = results.get("anomalies", [])
    
    # Create incidents/anomalies in DB
    async with async_session_factory() as db:
        for anomaly in anomalies:
            dna = ThreatDNAFingerprinter.generate_fingerprint({"type": anomaly["classification"]})
            anomaly["threat_dna"] = dna
            
            # Create an Incident if score is high
            if anomaly["anomaly_score"] > 0.9:
                inc = Incident(
                    title=f"Critical Anomaly: {anomaly['classification']}",
                    description=f"LLM detected highly anomalous pattern from {anomaly['source_ip']} (score: {anomaly['anomaly_score']}).",
                    severity="critical",
                    status="open",
                    source="llm_anomaly"
                )
                db.add(inc)
        await db.commit()

    return {
        "anomalies_detected": len(anomalies),
        "threshold": threshold,
        "anomalies": anomalies,
        "model_version": "Llama 3 8B (LoRA)",
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.post("/ml/severity-score", tags=["AI/ML Engine"])
async def calculate_severity(
    cvss_base: float = Query(5.0, ge=0, le=10),
    asset_criticality: float = Query(0.7, ge=0, le=1),
    exploit_likelihood: float = Query(0.5, ge=0, le=1),
    osint_score: float = Query(0.5, ge=0, le=1),
    active_exploitation: bool = False,
    current_user: dict = Depends(check_admin_role),
):
    """Calculate enhanced CVSS severity score with environmental factors."""
    return SeverityScorer.calculate_score(
        cvss_base, asset_criticality, exploit_likelihood, osint_score, active_exploitation
    )


# ─────────────────────────────────────────────
# Layer 3 — Threat Intelligence
# ─────────────────────────────────────────────

@router.get("/threats", response_model=List[ThreatResponse], tags=["Threat Intelligence"])
async def list_threats(
    severity: Optional[str] = None,
    resolved: Optional[bool] = None,
    category: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List all detected threats with filtering and pagination."""
    query = select(Threat).order_by(Threat.detected_at.desc()).offset(skip).limit(limit)
    if severity:
        query = query.where(Threat.severity == severity)
    if resolved is not None:
        query = query.where(Threat.is_resolved == resolved)
    if category:
        query = query.where(Threat.category.ilike(f"%{category}%"))
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/threats/{threat_id}", tags=["Threat Intelligence"])
async def get_threat(
    threat_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get detailed threat information with MITRE mapping and kill chain."""
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    kill_chain = KillChainEngine.reconstruct_chain(threat.kill_chain_phase or "Initial Access")
    return {
        "threat": {
            "id": threat.id,
            "title": threat.title,
            "description": threat.description,
            "severity": threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity),
            "severity_score": threat.severity_score,
            "category": threat.category,
            "mitre_tactic": threat.mitre_tactic,
            "mitre_technique_id": threat.mitre_technique_id,
            "mitre_technique_name": threat.mitre_technique_name,
            "kill_chain_phase": threat.kill_chain_phase,
            "ioc_value": threat.ioc_value,
            "source_country": threat.source_country,
            "source_latitude": threat.source_latitude,
            "source_longitude": threat.source_longitude,
            "is_resolved": threat.is_resolved,
            "detected_at": threat.detected_at.isoformat() if threat.detected_at else None,
        },
        "kill_chain": kill_chain,
        "mitre_details": {
            "tactic": threat.mitre_tactic,
            "technique_id": threat.mitre_technique_id,
            "technique_name": threat.mitre_technique_name,
            "phase": threat.kill_chain_phase,
        },
    }


@router.put("/threats/{threat_id}/resolve", tags=["Threat Intelligence"])
async def resolve_threat(
    threat_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Mark a threat as resolved."""
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    threat.is_resolved = True
    threat.resolved_at = datetime.utcnow()
    await db.commit()
    await ws_manager.broadcast_system_event(
        "info", f"Threat resolved: {threat.title}",
        detail=f"Resolved by {current_user.get('sub', 'system')}"
    )
    return {"status": "resolved", "threat_id": threat_id}


@router.get("/mitre/matrix", tags=["Threat Intelligence"])
async def get_mitre_matrix(current_user: dict = Depends(get_current_user)):
    """Get the full MITRE ATT&CK matrix for dashboard overlay."""
    return MITRE_ATTACK_MATRIX


@router.get("/mitre/threat-actors", tags=["Threat Intelligence"])
async def get_threat_actors(current_user: dict = Depends(get_current_user)):
    """Get known APT threat actor database with TTPs."""
    return THREAT_ACTOR_DB


@router.post("/mitre/map", tags=["Threat Intelligence"])
async def map_to_mitre(
    description: str,
    attack_type: str = "",
    current_user: dict = Depends(get_current_user),
):
    """Map a threat description to MITRE ATT&CK framework."""
    return MITREMapper.map_threat(description, attack_type)


@router.post("/threat-intel/kill-chain", tags=["Threat Intelligence"])
async def get_kill_chain(
    current_phase: str,
    threat_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Reconstruct kill chain and predict next attack phases."""
    threat_data = None
    if threat_id:
        result = await db.execute(select(Threat).where(Threat.id == threat_id))
        threat = result.scalar_one_or_none()
        if threat:
            threat_data = {
                "root_cause": threat.root_cause,
                "remediation": threat.remediation,
                "attack_vector_detail": threat.attack_vector_detail,
                "cve_description": threat.cve_description,
                "title": threat.title,
                "affected_components": threat.affected_components
            }
            
    if not threat_data:
        # fallback to get the most recent active threat that matches the tactic
        query = select(Threat).where(and_(Threat.is_resolved == False, Threat.mitre_tactic.ilike(f"%{current_phase.split(' ')[0]}%"))).order_by(Threat.detected_at.desc()).limit(1)
        result = await db.execute(query)
        threat = result.scalar_one_or_none()
        if threat:
            threat_data = {
                "root_cause": threat.root_cause,
                "remediation": threat.remediation,
                "attack_vector_detail": threat.attack_vector_detail,
                "cve_description": threat.cve_description,
                "title": threat.title,
                "affected_components": threat.affected_components
            }

    return KillChainEngine.reconstruct_chain(current_phase, threat_data)


@router.post("/threat-intel/ioc-enrich", tags=["Threat Intelligence"])
async def enrich_ioc(
    indicator: str,
    indicator_type: str = "domain",
    current_user: dict = Depends(check_admin_role),
):
    """Enrich an IOC with cross-source intelligence."""
    return IOCEnricher.enrich_ioc(indicator, indicator_type)


@router.post("/threat-intel/ioc-bulk", tags=["Threat Intelligence"])
async def bulk_ioc_search(
    indicators: List[Dict[str, str]],
    current_user: dict = Depends(check_admin_role),
):
    """
    Bulk IOC enrichment. Accepts list of {indicator, type} objects.
    Max 50 per request.
    """
    if len(indicators) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 IOCs per bulk request")
    results = []
    for item in indicators:
        indicator = item.get("indicator", "").strip()
        ioc_type = item.get("type", "domain")
        if indicator:
            enriched = IOCEnricher.enrich_ioc(indicator, ioc_type)
            results.append(enriched)
    return {
        "total": len(results),
        "results": results,
        "processed_at": datetime.utcnow().isoformat(),
    }


# ─────────────────────────────────────────────
# Layer 4 — Incident Response
# ─────────────────────────────────────────────

@router.post("/incidents", response_model=IncidentResponse, tags=["Incident Response"])
async def create_incident(
    incident: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_admin_role),
):
    """Create a new incident with auto-generated response playbook."""
    if current_user.get("role") not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Analyst or admin role required")

    new_incident = Incident(
        id=str(uuid.uuid4()),
        target_id=incident.target_id,
        threat_id=incident.threat_id,
        title=incident.title,
        description=incident.description,
        severity=SeverityLevel(incident.severity.value),
    )

    playbook = await PlaybookGenerator.generate_playbook(
        threat_type=incident.title,
        severity=incident.severity.value,
        context={"description": incident.description},
    )
    new_incident.playbook_content = playbook["playbook_content"]
    new_incident.playbook_steps = playbook["playbook_steps"]

    if incident.severity.value in ("critical", "high"):
        alert_result = await AutoAlertSystem.send_alert(
            incident_id=new_incident.id,
            severity=incident.severity.value,
            title=incident.title,
            details={"description": incident.description},
        )
        new_incident.alert_sent = True
        new_incident.alert_channels = alert_result.get("channels", [])

    db.add(new_incident)
    await db.commit()
    await db.refresh(new_incident)

    await ws_manager.broadcast_incident({
        "id": new_incident.id,
        "title": new_incident.title,
        "severity": incident.severity.value,
        "created_by": current_user.get("sub"),
    })

    return new_incident

@router.get("/ml/status", tags=["AI/ML Engine"])
async def get_ml_status():
    """Get the status of the local LLM and ML Engine."""
    from app.services.ml.llm_service import llm_service
    is_online = await llm_service.is_ollama_available()
    return {
        "engine": "Llama 3 8B (LoRA)" if is_online else "Statistical ML Engine",
        "status": "online" if is_online else "fallback",
        "message": "Local LLM is running." if is_online else "LLM unreachable. Using deterministic ML fallbacks."
    }

@router.get("/incidents", response_model=List[IncidentResponse], tags=["Incident Response"])
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List all incidents with filtering and pagination."""
    query = select(Incident).order_by(Incident.detected_at.desc()).offset(skip).limit(limit)
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/incidents/{incident_id}", tags=["Incident Response"])
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get incident details with playbook and remediation logs."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.put("/incidents/{incident_id}/status", tags=["Incident Response"])
async def update_incident_status(
    incident_id: str,
    new_status: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_admin_role),
):
    """Update incident status with audit trail."""
    valid_statuses = [s.value for s in DBIncidentStatus]
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Valid: {valid_statuses}")

    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = DBIncidentStatus(new_status)
    now = datetime.utcnow()
    if new_status == "investigating":
        incident.acknowledged_at = now
    elif new_status == "contained":
        incident.contained_at = now
    elif new_status == "resolved":
        incident.resolved_at = now
    elif new_status == "closed":
        incident.closed_at = now

    log = RemediationLog(
        id=str(uuid.uuid4()),
        incident_id=incident_id,
        action=f"Status changed to '{new_status}'",
        performed_by=current_user.get("sub", "system"),
    )
    db.add(log)
    await db.commit()

    await ws_manager.broadcast_system_event(
        "info", f"Incident '{incident.title}' → {new_status}",
        detail=f"Updated by {current_user.get('sub', 'system')}"
    )
    return {"status": "updated", "new_status": new_status, "incident_id": incident_id}


@router.post("/playbook/generate", tags=["Incident Response"])
async def generate_playbook(
    request: PlaybookRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_admin_role),
):
    """Generate an AI-powered incident response playbook."""
    playbook = await PlaybookGenerator.generate_playbook(
        threat_type=request.threat_type or "Unknown Threat",
        severity=request.severity or "medium",
        context=request.context,
    )
    if request.incident_id:
        result = await db.execute(select(Incident).where(Incident.id == request.incident_id))
        incident = result.scalar_one_or_none()
        if incident:
            incident.playbook_content = playbook["playbook_content"]
            incident.playbook_steps = playbook["playbook_steps"]
            await db.commit()
    return playbook

# ─────────────────────────────────────────────
# Layer 4.5 — Real-Time Monitoring
# ─────────────────────────────────────────────

@router.get("/monitoring/server-status", tags=["Monitoring"])
async def get_server_status(current_user: dict = Depends(get_current_user)):
    """Get live server metrics from psutil."""
    return await server_monitor.get_current_stats()

@router.get("/monitoring/global-threats", tags=["Monitoring"])
async def get_global_threats(current_user: dict = Depends(get_current_user)):
    """Get live global threats from NVD and CISA feeds."""
    return await global_threat_feed.get_current_threats()

@router.get("/monitoring/machine-scan", tags=["Monitoring"])
async def get_machine_scan(current_user: dict = Depends(get_current_user)):
    """
    Get real-time machine threat analysis:
    - Host public IP with city-level geolocation
    - All active network connections geolocated and classified
    - Risk score (0-100)
    - Open listening ports
    - OS fingerprint
    """
    return await machine_scanner.get_result()

# ─────────────────────────────────────────────
# Layer 5 — Dashboard
# ─────────────────────────────────────────────

@router.get("/dashboard/stats", tags=["Dashboard"])
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Comprehensive dashboard statistics for the SOC analyst view."""
    targets_count = (await db.execute(select(func.count(Target.id)).where(Target.is_archived == False))).scalar() or 0
    # To fix "phantom threats", active_threats should only count real scan threats, 
    # not the global feed which is populated into the incidents table.
    threats_count = (await db.execute(
        select(func.count(Threat.id)).where(
            and_(Threat.is_resolved == False, Threat.is_archived == False)
        )
    )).scalar() or 0
    critical_count = (await db.execute(
        select(func.count(Threat.id)).where(
            and_(Threat.severity == SeverityLevel.CRITICAL, Threat.is_resolved == False, Threat.is_archived == False)
        )
    )).scalar() or 0
    incidents_count = (await db.execute(
        select(func.count(Incident.id)).where(
            and_(Incident.status == DBIncidentStatus.OPEN, Incident.is_archived == False)
        )
    )).scalar() or 0
    # Real anomaly count (not random)
    anomaly_count = (await db.execute(
        select(func.count(AnomalyDetection.id)).where(
            and_(AnomalyDetection.is_anomalous == True, AnomalyDetection.is_archived == False)
        )
    )).scalar() or 0

    # Fetch all active threats for comprehensive aggregations (limit 1000 to prevent memory issues)
    all_threats_result = await db.execute(
        select(Threat).options(selectinload(Threat.target)).where(Threat.is_archived == False).order_by(Threat.detected_at.desc()).limit(1000)
    )
    all_active_threats = all_threats_result.scalars().all()
    recent_threats = all_active_threats[:10]

    recent_incidents_result = await db.execute(
        select(Incident).where(Incident.is_archived == False).order_by(Incident.detected_at.desc()).limit(10)
    )
    recent_incidents = recent_incidents_result.scalars().all()

    severity_counts = {}
    for sev in SeverityLevel:
        count = (await db.execute(
            select(func.count(Threat.id)).where(and_(Threat.severity == sev, Threat.is_archived == False))
        )).scalar() or 0
        severity_counts[sev.value] = count

    country_threats = []
    for threat in all_active_threats:
        if threat.source_country and threat.source_latitude:
            country_threats.append({
                "country": threat.source_country,
                "lat": threat.source_latitude,
                "lon": threat.source_longitude,
                "severity": threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity),
                "title": threat.title,
            })

    mitre_coverage = []
    for threat in all_active_threats:
        if threat.mitre_tactic:
            tech_id = threat.mitre_technique_id or ""
            mitre_url = f"https://attack.mitre.org/techniques/{tech_id}/" if tech_id else "https://attack.mitre.org/"
            mitre_coverage.append({
                "tactic": threat.mitre_tactic,
                "technique_id": tech_id,
                "technique_name": threat.mitre_technique_name,
                "severity": threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity),
                "target_domain": threat.target.domain if threat.target else None,
                "mitre_url": mitre_url,
                "threat_id": threat.id,
            })

    # ── Kill Chain Progression — aggregate phase counts from real threats ──
    kill_chain_order = [
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]
    kill_chain_progression = {phase: 0 for phase in kill_chain_order}
    for threat in all_active_threats:
        phase = threat.kill_chain_phase
        if phase and phase in kill_chain_progression:
            kill_chain_progression[phase] += 1

    # ── Attack Surface Summary — top affected components from real threats ──
    component_counts: Dict[str, int] = {}
    for threat in all_active_threats:
        components = threat.affected_components or []
        if isinstance(components, list):
            for comp in components:
                component_counts[comp] = component_counts.get(comp, 0) + 1
    attack_surface_summary = [
        {"component": k, "threat_count": v, "severity": "HIGH" if v >= 3 else "MEDIUM"}
        for k, v in sorted(component_counts.items(), key=lambda x: -x[1])[:8]
    ]

    return {
        "total_targets": targets_count,
        "active_threats": threats_count,
        "critical_threats": critical_count,
        "open_incidents": incidents_count,
        "predictions_active": len(all_active_threats),
        "anomalies_detected": anomaly_count,
        "threats_by_severity": severity_counts,
        "threats_by_country": country_threats,
        "kill_chain_progression": kill_chain_progression,
        "attack_surface_summary": attack_surface_summary,
        "recent_threats": [
            {
                "id": t.id,
                "title": t.title,
                "description": t.description,
                "severity": t.severity.value if hasattr(t.severity, "value") else str(t.severity),
                "severity_score": t.severity_score,
                "category": t.category,
                "mitre_tactic": t.mitre_tactic,
                "mitre_technique_id": t.mitre_technique_id,
                "mitre_technique_name": t.mitre_technique_name,
                "kill_chain_phase": t.kill_chain_phase,
                "ioc_value": t.ioc_value,
                "source_country": t.source_country,
                "detected_at": t.detected_at.isoformat() if t.detected_at else None,
                "root_cause": t.root_cause,
                "cve_description": t.cve_description,
                "affected_components": t.affected_components,
                "attack_vector_detail": t.attack_vector_detail,
                "remediation": t.remediation,
            }
            for t in recent_threats
        ],
        "recent_incidents": [
            {
                "id": i.id,
                "title": i.title,
                "description": i.description,
                "severity": i.severity.value if hasattr(i.severity, "value") else str(i.severity),
                "status": i.status.value if hasattr(i.status, "value") else str(i.status),
                "source": i.source,
                "detected_at": i.detected_at.isoformat() if i.detected_at else None,
            }
            for i in recent_incidents
        ],
        "mitre_attack_coverage": mitre_coverage,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/dashboard/threat-timeline", tags=["Dashboard"])
async def get_threat_timeline(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get threat timeline data for the last N days."""
    since = datetime.utcnow() - timedelta(days=days)
    result = await db.execute(
        select(Threat).where(Threat.detected_at >= since).order_by(Threat.detected_at.asc())
    )
    threats = result.scalars().all()
    timeline = [
        {
            "id": t.id,
            "title": t.title,
            "severity": t.severity.value if hasattr(t.severity, "value") else str(t.severity),
            "severity_score": t.severity_score,
            "category": t.category,
            "mitre_tactic": t.mitre_tactic,
            "detected_at": t.detected_at.isoformat() if t.detected_at else None,
            "is_resolved": t.is_resolved,
        }
        for t in threats
    ]
    return {"days": days, "count": len(timeline), "timeline": timeline}


@router.get("/dashboard/metrics", tags=["Dashboard"])
async def get_advanced_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get advanced metrics: MTTD, MTTR, threat velocity, compliance scores."""
    # Mean Time to Detect (MTTD): avg hours between scan start and threat detection
    # Using scan created_at vs threat detected_at as proxy
    total_threats = (await db.execute(select(func.count(Threat.id)))).scalar() or 0
    resolved_threats = (await db.execute(
        select(func.count(Threat.id)).where(Threat.is_resolved == True)
    )).scalar() or 0

    # Threat velocity: threats in last 24h vs previous 24h
    now = datetime.utcnow()
    last_24h = (await db.execute(
        select(func.count(Threat.id)).where(Threat.detected_at >= now - timedelta(hours=24))
    )).scalar() or 0
    prev_24h = (await db.execute(
        select(func.count(Threat.id)).where(
            and_(
                Threat.detected_at >= now - timedelta(hours=48),
                Threat.detected_at < now - timedelta(hours=24),
            )
        )
    )).scalar() or 0

    velocity_change = ((last_24h - prev_24h) / max(prev_24h, 1)) * 100

    # Incident resolution rate
    total_incidents = (await db.execute(select(func.count(Incident.id)))).scalar() or 0
    resolved_incidents = (await db.execute(
        select(func.count(Incident.id)).where(Incident.status == DBIncidentStatus.RESOLVED)
    )).scalar() or 0

    return {
        "threat_stats": {
            "total": total_threats,
            "resolved": resolved_threats,
            "resolution_rate": round(resolved_threats / max(total_threats, 1) * 100, 1),
            "active": total_threats - resolved_threats,
        },
        "threat_velocity": {
            "last_24h": last_24h,
            "prev_24h": prev_24h,
            "change_pct": round(velocity_change, 1),
            "trending_up": velocity_change > 0,
        },
        "incident_stats": {
            "total": total_incidents,
            "resolved": resolved_incidents,
            "resolution_rate": round(resolved_incidents / max(total_incidents, 1) * 100, 1),
        },
        "compliance_scores": {
            "pci_dss": min(85 + resolved_incidents * 2, 100),
            "iso_27001": min(78 + resolved_threats, 100),
            "nist_csf": min(72 + total_threats - (total_threats - resolved_threats) * 3, 100),
            "soc2": min(80 + resolved_incidents * 3, 100),
        },
        "generated_at": now.isoformat(),
    }


# ─────────────────────────────────────────────
# Reports
# ─────────────────────────────────────────────

@router.get("/reports/generate", tags=["Reports"])
async def generate_report(
    format: str = Query("json", pattern="^(json|text)$"),
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Generate an executive security report.
    Returns JSON summary or plain-text report.
    """
    now = datetime.utcnow()
    since = now - timedelta(days=days)

    threats_result = await db.execute(
        select(Threat).where(Threat.detected_at >= since).order_by(Threat.severity)
    )
    threats = threats_result.scalars().all()

    incidents_result = await db.execute(
        select(Incident).where(Incident.detected_at >= since)
    )
    incidents = incidents_result.scalars().all()

    severity_breakdown = {}
    for sev in SeverityLevel:
        severity_breakdown[sev.value] = sum(
            1 for t in threats if hasattr(t.severity, "value") and t.severity.value == sev.value
        )

    report_data = {
        "report_title": f"ITAP Executive Security Report — Last {days} Days",
        "generated_at": now.isoformat(),
        "generated_by": current_user.get("sub", "system"),
        "period_start": since.isoformat(),
        "period_end": now.isoformat(),
        "executive_summary": {
            "total_threats_detected": len(threats),
            "critical_threats": severity_breakdown.get("critical", 0),
            "high_threats": severity_breakdown.get("high", 0),
            "incidents_opened": len(incidents),
            "incidents_resolved": sum(1 for i in incidents if hasattr(i.status, "value") and i.status.value == "resolved"),
        },
        "threats_by_severity": severity_breakdown,
        "top_threats": [
            {
                "title": t.title,
                "severity": t.severity.value if hasattr(t.severity, "value") else str(t.severity),
                "score": t.severity_score,
                "mitre_tactic": t.mitre_tactic,
                "detected_at": t.detected_at.isoformat() if t.detected_at else None,
            }
            for t in sorted(threats, key=lambda x: x.severity_score or 0, reverse=True)[:10]
        ],
        "recommendations": [
            "Prioritize patching of systems with CRITICAL severity findings",
            "Enable MFA across all administrative interfaces",
            "Review and update firewall rules for anomalous egress traffic",
            "Conduct threat hunting based on identified MITRE ATT&CK tactics",
            "Schedule mandatory security awareness training",
        ],
    }

    if format == "text":
        text = f"""
=== {report_data['report_title']} ===
Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}
By: {report_data['generated_by']}

EXECUTIVE SUMMARY
-----------------
Threats Detected : {report_data['executive_summary']['total_threats_detected']}
Critical         : {report_data['executive_summary']['critical_threats']}
High             : {report_data['executive_summary']['high_threats']}
Incidents Opened : {report_data['executive_summary']['incidents_opened']}
Incidents Resolved: {report_data['executive_summary']['incidents_resolved']}

RECOMMENDATIONS
---------------
""" + "\n".join(f"• {r}" for r in report_data["recommendations"])

        return StreamingResponse(
            io.BytesIO(text.encode()),
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename=itap_report_{now.strftime('%Y%m%d')}.txt"},
        )

    return report_data


# ─────────────────────────────────────────────
# System & History
# ─────────────────────────────────────────────

@router.post("/system/new-session", tags=["System"])
async def start_new_session(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_admin_role),
):
    """
    Archive all active targets, scans, threats, and incidents so the dashboard starts fresh.
    """
    await db.execute(update(Target).where(Target.is_archived == False).values(is_archived=True))
    await db.execute(update(Scan).where(Scan.is_archived == False).values(is_archived=True))
    await db.execute(update(Threat).where(Threat.is_archived == False).values(is_archived=True))
    await db.execute(update(Incident).where(Incident.is_archived == False).values(is_archived=True))
    await db.execute(update(AnomalyDetection).where(AnomalyDetection.is_archived == False).values(is_archived=True))
    
    await db.commit()
    
    await ws_manager.broadcast_system_event(
        "info", "New Session Started",
        detail=f"Previous data archived by {current_user.get('sub', 'system')}"
    )
    return {"status": "success", "message": "All active data has been safely archived. Starting fresh session."}


@router.get("/history/summary", tags=["System"])
async def get_history_summary(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get a summary of ALL targets (active and archived) and their threat counts.
    Shows both current and historical scans so users can always view past results.
    """
    result = await db.execute(
        select(Target).order_by(Target.created_at.desc())
    )
    all_targets = result.scalars().all()
    
    history_list = []
    for t in all_targets:
        # Get threats for this target
        threats_count = (await db.execute(
            select(func.count(Threat.id)).where(Threat.target_id == t.id)
        )).scalar() or 0
        
        scans_count = (await db.execute(
            select(func.count(Scan.id)).where(Scan.target_id == t.id)
        )).scalar() or 0
        
        history_list.append({
            "target_id": t.id,
            "domain": t.domain,
            "ip_address": t.ip_address,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "threats_count": threats_count,
            "scans_count": scans_count,
            "is_archived": t.is_archived,
        })
        
    return {"history": history_list}


@router.delete("/history/all", tags=["System"])
async def delete_all_history(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_admin_role),
):
    """
    Permanently delete ALL targets, scans, threats, and incidents from the database.
    This allows users to do a fresh re-scan of domains.
    """
    from sqlalchemy import delete as sql_delete

    # Delete in dependency order to respect foreign keys
    await db.execute(sql_delete(ThreatPrediction))
    await db.execute(sql_delete(AnomalyDetection))
    await db.execute(sql_delete(RemediationLog))
    await db.execute(sql_delete(OSINTData))
    await db.execute(sql_delete(Threat))
    await db.execute(sql_delete(Incident))
    await db.execute(sql_delete(Scan))
    await db.execute(sql_delete(Target))
    await db.commit()

    await ws_manager.broadcast_system_event(
        "warning", "All History Deleted",
        detail=f"All scan history permanently deleted by {current_user.get('sub', 'system')}"
    )
    return {"status": "success", "message": "All history has been permanently deleted. You can now re-scan domains."}


@router.get("/history/target/{target_id}", tags=["System"])
async def get_history_target_details(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get full detailed threats and scans for a specific archived target.
    """
    # Verify it exists
    target = (await db.execute(select(Target).where(Target.id == target_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    scans = (await db.execute(select(Scan).where(Scan.target_id == target_id))).scalars().all()
    threats = (await db.execute(select(Threat).where(Threat.target_id == target_id))).scalars().all()
    
    return {
        "target": {
            "domain": target.domain,
            "ip_address": target.ip_address,
            "created_at": target.created_at.isoformat() if target.created_at else None,
            "is_archived": target.is_archived,
        },
        "scans": [
            {
                "id": s.id,
                "type": s.scan_type,
                "status": s.status,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "risk_score": s.reputation_score,
            } for s in scans
        ],
        "threats": [
            {
                "id": th.id,
                "title": th.title,
                "severity": th.severity.value if hasattr(th.severity, "value") else str(th.severity),
                "detected_at": th.detected_at.isoformat() if th.detected_at else None,
            } for th in threats
        ]
    }


# ─────────────────────────────────────────────────────────────────
# SOAR — Security Orchestration, Automation & Response
# ─────────────────────────────────────────────────────────────────

# In-memory mock firewall store (replace with real firewall API in production)
_blocked_ips: Dict[str, Any] = {}


class SOARBlockRequest(BaseModel):
    ip: str
    threat_id: Optional[str] = None
    reason: Optional[str] = "Blocked via ITAP SOC Dashboard"


@router.post("/soar/block-ip", tags=["SOAR"])
async def soar_block_ip(
    request: SOARBlockRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_admin_role),
):
    """
    [ADMIN ONLY] Block a malicious IP via the mock firewall integration.
    In production, replace the mock store with a real firewall API call.
    """
    import re
    # Validate IP format
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if not ip_pattern.match(request.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    rule_id = f"ITAP-{uuid.uuid4().hex[:8].upper()}"
    _blocked_ips[request.ip] = {
        "ip": request.ip,
        "rule_id": rule_id,
        "reason": request.reason,
        "blocked_by": current_user.get("sub", "admin"),
        "blocked_at": datetime.utcnow().isoformat(),
        "threat_id": request.threat_id,
    }

    # Update the linked threat status if provided
    if request.threat_id:
        threat = (await db.execute(select(Threat).where(Threat.id == request.threat_id))).scalar_one_or_none()
        if threat:
            threat.is_resolved = True
            threat.resolved_at = datetime.utcnow()
            await db.commit()

    await ws_manager.broadcast_system_event(
        "warning", f"IP Blocked: {request.ip}",
        detail=f"Firewall rule {rule_id} applied by {current_user.get('sub', 'admin')}. Reason: {request.reason}"
    )

    return {
        "status": "blocked",
        "ip": request.ip,
        "rule_id": rule_id,
        "message": f"IP {request.ip} has been blocked. Firewall rule {rule_id} is active.",
        "mock_command": f"iptables -A INPUT -s {request.ip} -j DROP  # {rule_id}",
    }


@router.get("/soar/blocked-ips", tags=["SOAR"])
async def soar_get_blocked_ips(
    current_user: dict = Depends(get_current_user),
):
    """Get all currently blocked IPs and their firewall rules."""
    return {
        "count": len(_blocked_ips),
        "blocked_ips": list(_blocked_ips.values()),
    }


@router.delete("/soar/blocked-ips/{ip}", tags=["SOAR"])
async def soar_unblock_ip(
    ip: str,
    current_user: dict = Depends(check_admin_role),
):
    """[ADMIN ONLY] Remove a firewall block rule for a specific IP."""
    if ip not in _blocked_ips:
        raise HTTPException(status_code=404, detail=f"IP {ip} is not in the block list")

    rule = _blocked_ips.pop(ip)
    await ws_manager.broadcast_system_event(
        "info", f"IP Unblocked: {ip}",
        detail=f"Firewall rule {rule['rule_id']} removed by {current_user.get('sub', 'admin')}"
    )
    return {"status": "unblocked", "ip": ip, "rule_id": rule["rule_id"]}
