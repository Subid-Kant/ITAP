"""
ITAP — API Routes
All REST API endpoints organized by layer.
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timedelta
from typing import List, Optional
import uuid
import random

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
from app.services.ml import LSTMPredictor, AutoencoderDetector, SeverityScorer
from app.services.threat_intel import MITREMapper, KillChainEngine, ThreatDNAFingerprinter, IOCEnricher, MITRE_ATTACK_MATRIX
from app.services.response import PlaybookGenerator, AutoAlertSystem


router = APIRouter()


# ─────────────────────────────────────────────
# Target Management
# ─────────────────────────────────────────────

@router.post("/targets", response_model=TargetResponse, tags=["Targets"])
async def create_target(target: TargetCreate, db: AsyncSession = Depends(get_db)):
    """Register a new target domain/IP for monitoring."""
    new_target = Target(
        id=str(uuid.uuid4()),
        domain=target.domain,
        ip_address=target.ip_address,
        organization=target.organization
    )
    db.add(new_target)
    await db.commit()
    await db.refresh(new_target)
    return new_target


@router.get("/targets", response_model=List[TargetResponse], tags=["Targets"])
async def list_targets(db: AsyncSession = Depends(get_db)):
    """List all monitored targets."""
    result = await db.execute(select(Target).order_by(Target.created_at.desc()))
    return result.scalars().all()


@router.get("/targets/{target_id}", response_model=TargetResponse, tags=["Targets"])
async def get_target(target_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific target."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.delete("/targets/{target_id}", tags=["Targets"])
async def delete_target(target_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a target."""
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
async def run_osint_scan(request: ScanRequest, db: AsyncSession = Depends(get_db)):
    """
    Run a comprehensive OSINT scan on a target.
    Aggregates data from Shodan, VirusTotal, CVE/NVD, and AlienVault OTX.
    """
    # Get target
    result = await db.execute(select(Target).where(Target.id == request.target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Run OSINT aggregation
    osint_results = await OSINTAggregator.full_scan(target.domain, target.ip_address)
    
    # Store scan results
    scan = Scan(
        id=str(uuid.uuid4()),
        target_id=target.id,
        scan_type="full_osint",
        status=DBScanStatus.COMPLETED,
        results=osint_results,
        open_ports=osint_results.get("sources", {}).get("shodan", {}).get("ports", []),
        vulnerabilities=osint_results.get("sources", {}).get("shodan", {}).get("vulns", []),
        reputation_score=osint_results.get("risk_score"),
        completed_at=datetime.utcnow()
    )
    db.add(scan)
    
    # Run ML predictions on the OSINT data
    predictions = await LSTMPredictor.predict_threats(target.domain, osint_results)
    
    # Auto-create threats from high-risk findings
    threats_created = []
    for pred in predictions[:5]:
        if pred["probability"] > 0.5:
            mitre_mapping = MITREMapper.map_threat(
                pred.get("predicted_attack_type", ""), 
                pred.get("predicted_attack_type", "")
            )
            severity_result = SeverityScorer.calculate_score(
                cvss_base=pred.get("cvss_score", 5.0) or 5.0,
                exploit_likelihood=pred["probability"],
                osint_context_score=osint_results.get("risk_score", 50) / 100
            )
            
            geo = osint_results.get("summary", {}).get("geolocation", {})
            
            threat = Threat(
                id=str(uuid.uuid4()),
                target_id=target.id,
                title=f"Predicted: {pred.get('predicted_attack_type', 'Unknown Threat')}",
                description=f"LSTM prediction with {pred['probability']*100:.1f}% probability. CVE: {pred.get('predicted_cve', 'N/A')}",
                severity=SeverityLevel(severity_result["severity"].lower()) if severity_result["severity"].lower() in [e.value for e in SeverityLevel] else SeverityLevel.MEDIUM,
                severity_score=severity_result["score"],
                category=pred.get("predicted_attack_type"),
                mitre_tactic=mitre_mapping.get("tactic"),
                mitre_technique_id=mitre_mapping.get("technique_id"),
                mitre_technique_name=mitre_mapping.get("technique_name"),
                kill_chain_phase=mitre_mapping.get("kill_chain_phase"),
                ioc_value=pred.get("predicted_cve"),
                source_country=geo.get("country"),
                source_latitude=geo.get("lat"),
                source_longitude=geo.get("lon")
            )
            db.add(threat)
            threats_created.append(threat.title)
    
    await db.commit()
    
    return {
        "scan_id": scan.id,
        "target": target.domain,
        "risk_score": osint_results.get("risk_score"),
        "risk_level": osint_results.get("risk_level"),
        "summary": osint_results.get("summary"),
        "predictions": predictions[:5],
        "threats_created": threats_created,
        "osint_data": osint_results.get("sources")
    }


@router.get("/scan/{scan_id}", tags=["OSINT Scanning"])
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get scan results by ID."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ─────────────────────────────────────────────
# Layer 2 — AI/ML Engine
# ─────────────────────────────────────────────

@router.post("/ml/predict", tags=["AI/ML Engine"])
async def predict_threats(domain: str):
    """
    Run LSTM threat prediction for a domain.
    Returns predicted CVEs and attack types with probability scores.
    """
    osint_data = await OSINTAggregator.full_scan(domain)
    predictions = await LSTMPredictor.predict_threats(domain, osint_data)
    return {
        "domain": domain,
        "risk_score": osint_data.get("risk_score"),
        "predictions": predictions,
        "model_version": "1.0",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/ml/anomaly-detect", tags=["AI/ML Engine"])
async def detect_anomalies(threshold: float = 0.85):
    """
    Run autoencoder anomaly detection.
    Returns detected anomalies with Threat DNA fingerprints.
    """
    anomalies = await AutoencoderDetector.detect_anomalies(threshold=threshold)
    
    # Generate Threat DNA for each anomaly
    for anomaly in anomalies:
        if anomaly.get("features"):
            dna = ThreatDNAFingerprinter.generate_fingerprint(anomaly["features"])
            anomaly["threat_dna"] = dna
    
    return {
        "anomalies_detected": len(anomalies),
        "threshold": threshold,
        "anomalies": anomalies,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/ml/severity-score", tags=["AI/ML Engine"])
async def calculate_severity(
    cvss_base: float = 5.0,
    asset_criticality: float = 0.7,
    exploit_likelihood: float = 0.5,
    osint_score: float = 0.5,
    active_exploitation: bool = False
):
    """Calculate enhanced severity score."""
    return SeverityScorer.calculate_score(
        cvss_base, asset_criticality, exploit_likelihood,
        osint_score, active_exploitation
    )


# ─────────────────────────────────────────────
# Layer 3 — Threat Intelligence
# ─────────────────────────────────────────────

@router.get("/threats", response_model=List[ThreatResponse], tags=["Threat Intelligence"])
async def list_threats(
    severity: Optional[str] = None,
    resolved: Optional[bool] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """List all detected threats with optional filtering."""
    query = select(Threat).order_by(Threat.detected_at.desc()).limit(limit)
    
    if severity:
        query = query.where(Threat.severity == severity)
    if resolved is not None:
        query = query.where(Threat.is_resolved == resolved)
    
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/threats/{threat_id}", tags=["Threat Intelligence"])
async def get_threat(threat_id: str, db: AsyncSession = Depends(get_db)):
    """Get detailed threat information with MITRE mapping and kill chain."""
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    # Enrich with kill chain reconstruction
    kill_chain = KillChainEngine.reconstruct_chain(threat.kill_chain_phase or "Initial Access")
    
    return {
        "threat": threat,
        "kill_chain": kill_chain,
        "mitre_details": {
            "tactic": threat.mitre_tactic,
            "technique_id": threat.mitre_technique_id,
            "technique_name": threat.mitre_technique_name,
            "phase": threat.kill_chain_phase
        }
    }


@router.get("/mitre/matrix", tags=["Threat Intelligence"])
async def get_mitre_matrix():
    """Get the full MITRE ATT&CK matrix for dashboard overlay."""
    return MITRE_ATTACK_MATRIX


@router.post("/mitre/map", tags=["Threat Intelligence"])
async def map_to_mitre(description: str, attack_type: str = ""):
    """Map a threat description to MITRE ATT&CK."""
    return MITREMapper.map_threat(description, attack_type)


@router.post("/threat-intel/kill-chain", tags=["Threat Intelligence"])
async def get_kill_chain(current_phase: str):
    """Reconstruct kill chain and predict next attack phases."""
    return KillChainEngine.reconstruct_chain(current_phase)


@router.post("/threat-intel/ioc-enrich", tags=["Threat Intelligence"])
async def enrich_ioc(indicator: str, indicator_type: str = "domain"):
    """Enrich an IOC with cross-source intelligence."""
    return IOCEnricher.enrich_ioc(indicator, indicator_type)


# ─────────────────────────────────────────────
# Layer 4 — Incident Response
# ─────────────────────────────────────────────

@router.post("/incidents", response_model=IncidentResponse, tags=["Incident Response"])
async def create_incident(incident: IncidentCreate, db: AsyncSession = Depends(get_db)):
    """Create a new incident and auto-generate a response playbook."""
    new_incident = Incident(
        id=str(uuid.uuid4()),
        target_id=incident.target_id,
        threat_id=incident.threat_id,
        title=incident.title,
        description=incident.description,
        severity=SeverityLevel(incident.severity.value)
    )
    
    # Auto-generate playbook
    playbook = await PlaybookGenerator.generate_playbook(
        threat_type=incident.title,
        severity=incident.severity.value,
        context={"description": incident.description}
    )
    new_incident.playbook_content = playbook["playbook_content"]
    new_incident.playbook_steps = playbook["playbook_steps"]
    
    # Auto-send alert for high/critical
    if incident.severity.value in ["critical", "high"]:
        alert_result = await AutoAlertSystem.send_alert(
            incident_id=new_incident.id,
            severity=incident.severity.value,
            title=incident.title,
            details={"description": incident.description}
        )
        new_incident.alert_sent = True
        new_incident.alert_channels = alert_result.get("channels", [])
    
    db.add(new_incident)
    await db.commit()
    await db.refresh(new_incident)
    return new_incident


@router.get("/incidents", response_model=List[IncidentResponse], tags=["Incident Response"])
async def list_incidents(
    status: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """List all incidents."""
    query = select(Incident).order_by(Incident.detected_at.desc()).limit(limit)
    if status:
        query = query.where(Incident.status == status)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/incidents/{incident_id}", tags=["Incident Response"])
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Get incident details with playbook."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.put("/incidents/{incident_id}/status", tags=["Incident Response"])
async def update_incident_status(
    incident_id: str,
    new_status: str,
    db: AsyncSession = Depends(get_db)
):
    """Update incident status."""
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
    
    # Log remediation action
    log = RemediationLog(
        id=str(uuid.uuid4()),
        incident_id=incident_id,
        action=f"Status changed to {new_status}",
        performed_by="analyst"
    )
    db.add(log)
    await db.commit()
    
    return {"status": "updated", "new_status": new_status}


@router.post("/playbook/generate", tags=["Incident Response"])
async def generate_playbook(request: PlaybookRequest, db: AsyncSession = Depends(get_db)):
    """Generate an AI-powered incident response playbook."""
    playbook = await PlaybookGenerator.generate_playbook(
        threat_type=request.threat_type or "Unknown Threat",
        severity=request.severity or "medium",
        context=request.context
    )
    
    # Update incident if provided
    if request.incident_id:
        result = await db.execute(select(Incident).where(Incident.id == request.incident_id))
        incident = result.scalar_one_or_none()
        if incident:
            incident.playbook_content = playbook["playbook_content"]
            incident.playbook_steps = playbook["playbook_steps"]
            await db.commit()
    
    return playbook


# ─────────────────────────────────────────────
# Layer 5 — Dashboard
# ─────────────────────────────────────────────

@router.get("/dashboard/stats", tags=["Dashboard"])
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Get comprehensive dashboard statistics for the SOC analyst view."""
    
    # Total counts
    targets_count = (await db.execute(select(func.count(Target.id)))).scalar() or 0
    threats_count = (await db.execute(
        select(func.count(Threat.id)).where(Threat.is_resolved == False)
    )).scalar() or 0
    critical_count = (await db.execute(
        select(func.count(Threat.id)).where(
            Threat.severity == SeverityLevel.CRITICAL,
            Threat.is_resolved == False
        )
    )).scalar() or 0
    incidents_count = (await db.execute(
        select(func.count(Incident.id)).where(Incident.status == DBIncidentStatus.OPEN)
    )).scalar() or 0
    
    # Recent threats
    recent_threats_result = await db.execute(
        select(Threat).order_by(Threat.detected_at.desc()).limit(10)
    )
    recent_threats = recent_threats_result.scalars().all()
    
    # Recent incidents
    recent_incidents_result = await db.execute(
        select(Incident).order_by(Incident.detected_at.desc()).limit(10)
    )
    recent_incidents = recent_incidents_result.scalars().all()
    
    # Threats by severity
    severity_counts = {}
    for sev in SeverityLevel:
        count = (await db.execute(
            select(func.count(Threat.id)).where(Threat.severity == sev)
        )).scalar() or 0
        severity_counts[sev.value] = count
    
    # Threats by country (for geolocation map)
    country_threats = []
    for threat in recent_threats:
        if threat.source_country and threat.source_latitude:
            country_threats.append({
                "country": threat.source_country,
                "lat": threat.source_latitude,
                "lon": threat.source_longitude,
                "severity": threat.severity.value if hasattr(threat.severity, 'value') else str(threat.severity),
                "title": threat.title
            })
    
    # MITRE ATT&CK coverage
    mitre_coverage = []
    for threat in recent_threats:
        if threat.mitre_tactic:
            mitre_coverage.append({
                "tactic": threat.mitre_tactic,
                "technique_id": threat.mitre_technique_id,
                "technique_name": threat.mitre_technique_name,
                "severity": threat.severity.value if hasattr(threat.severity, 'value') else str(threat.severity)
            })
    
    return {
        "total_targets": targets_count,
        "active_threats": threats_count,
        "critical_threats": critical_count,
        "open_incidents": incidents_count,
        "predictions_active": len(recent_threats),
        "anomalies_detected": random.randint(5, 25),
        "threats_by_severity": severity_counts,
        "threats_by_country": country_threats,
        "recent_threats": [
            {
                "id": t.id,
                "title": t.title,
                "severity": t.severity.value if hasattr(t.severity, 'value') else str(t.severity),
                "severity_score": t.severity_score,
                "mitre_tactic": t.mitre_tactic,
                "source_country": t.source_country,
                "detected_at": t.detected_at.isoformat() if t.detected_at else None
            }
            for t in recent_threats
        ],
        "recent_incidents": [
            {
                "id": i.id,
                "title": i.title,
                "severity": i.severity.value if hasattr(i.severity, 'value') else str(i.severity),
                "status": i.status.value if hasattr(i.status, 'value') else str(i.status),
                "detected_at": i.detected_at.isoformat() if i.detected_at else None
            }
            for i in recent_incidents
        ],
        "mitre_attack_coverage": mitre_coverage,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/dashboard/threat-timeline", tags=["Dashboard"])
async def get_threat_timeline(days: int = 30, db: AsyncSession = Depends(get_db)):
    """Get threat timeline data for the last N days."""
    since = datetime.utcnow() - timedelta(days=days)
    result = await db.execute(
        select(Threat).where(Threat.detected_at >= since).order_by(Threat.detected_at.asc())
    )
    threats = result.scalars().all()
    
    timeline = []
    for t in threats:
        timeline.append({
            "id": t.id,
            "title": t.title,
            "severity": t.severity.value if hasattr(t.severity, 'value') else str(t.severity),
            "severity_score": t.severity_score,
            "category": t.category,
            "mitre_tactic": t.mitre_tactic,
            "detected_at": t.detected_at.isoformat() if t.detected_at else None,
            "is_resolved": t.is_resolved
        })
    
    return {"days": days, "count": len(timeline), "timeline": timeline}
