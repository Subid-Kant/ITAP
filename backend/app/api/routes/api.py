"""
ITAP v2.0 — API Routes
All REST API endpoints organized by layer.
Includes JWT authentication, pagination, WebSocket broadcasts, and PDF report generation.
"""
from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, update
from sqlalchemy.orm import selectinload
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import asyncio
import ipaddress
import io
import json
import logging
import socket
import uuid

from app.db.database import get_db
from app.models.models import (
    Target, Scan, OSINTData, ThreatPrediction, AnomalyDetection,
    Threat, Incident, RemediationLog, DashboardMetric, BlockedIP,
    SeverityLevel, ScanStatus as DBScanStatus, IncidentStatus as DBIncidentStatus
)
from app.schemas.schemas import (
    TargetCreate, TargetResponse, ScanRequest, ScanResponse,
    ThreatResponse, PredictionResponse, AnomalyResponse,
    IncidentCreate, IncidentResponse, PlaybookRequest, PlaybookResponse,
    DashboardStats
)
from app.services.osint import OSINTAggregator, NmapService
from app.services.ml.llm_service import LocalLLMService
from app.services.ml.output_validation import validate_predictions, screen_remediation
from app.services.ml.ml_engine import SeverityScorer, LSTMPredictor, AutoencoderDetector, get_model_status
from app.services.telemetry_service import TelemetryCollector
from app.services.threat_intel.threat_intel_service import (
    KillChainEngine, MITREMapper, ThreatDNAFingerprinter, IOCEnricher,
    MITRE_ATTACK_MATRIX, THREAT_ACTOR_DB,
)
from app.services.response.response_service import PlaybookGenerator, AutoAlertSystem
from app.services.monitoring.server_monitor import server_monitor
from app.services.monitoring.global_threat_feed import global_threat_feed
from app.services.monitoring.machine_scanner import machine_scanner
from app.core.config import settings
from app.core.security import (
    authenticate_user, create_access_token, create_refresh_token, get_current_user,
    require_roles, decode_token, guard_login, record_login_failure, clear_login_failures,
    revoke_token, is_token_revoked, BUILTIN_USERS,
)
from app.api.routes.ws import manager as ws_manager
from app.services.audit_service import (
    record_audit, audit_trail, audit_count, client_ip as _audit_client_ip,
    request_id_of,
)

logger = logging.getLogger("itap.api")
router = APIRouter()


# ─── Role-based Access Control ───────────────────────────────────────────────
# NOTE: this module previously declared TWO different `check_admin_role`
# functions. Because a route resolves the dependency name at decoration time,
# the later definition silently won for every route registered after it, making
# authorization depend on definition order. The single surviving definition
# lives just below the auth endpoints; prefer `require_roles(...)` from
# app.core.security when an endpoint admits more than one role.


# ─────────────────────────────────────────────
# Authentication
# ─────────────────────────────────────────────

def _client_ip(request: Request) -> str:
    """Best-effort client address, honouring a reverse proxy's X-Forwarded-For.

    Delegates to the audit helper so the throttle key, the audit row and the log
    line can never disagree about who the caller was.
    """
    return _audit_client_ip(request)


class LoginRequest(BaseModel):
    username: str
    password: str

class RefreshRequest(BaseModel):
    token: str

class LogoutRequest(BaseModel):
    # Optional: the access token is read from the Authorization header.
    refresh_token: Optional[str] = None

@router.post("/auth/login", tags=["Authentication"])
async def login(
    req: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate with username and password via JSON body.
    Returns JWT access token + refresh token.

    Throttled per (username, client IP). RateLimitMiddleware cannot cover this:
    it bypasses localhost entirely for developer convenience and only caps a whole
    IP address, so it never protects one account against password guessing.

    Successes, failures and throttles are all written to the audit trail: "has
    someone been guessing admin's password, from where, and how often" was not
    answerable from anywhere but the console.
    """
    throttle_key = f"{req.username}|{_client_ip(request)}"
    try:
        guard_login(throttle_key)
    except HTTPException:
        await record_audit(
            db, action="auth.login.throttled", actor=req.username, outcome="denied",
            detail="Too many failed attempts for this username/client pair",
            ip_address=_client_ip(request), request_id=request_id_of(request),
        )
        raise

    user = authenticate_user(req.username, req.password)
    if not user:
        record_login_failure(throttle_key)
        await record_audit(
            db, action="auth.login.failure", actor=req.username, outcome="failure",
            detail="Invalid credentials", ip_address=_client_ip(request),
            request_id=request_id_of(request),
        )
        # Same message for unknown user and wrong password so the endpoint does not
        # confirm which usernames exist.
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    clear_login_failures(throttle_key)
    access_token = create_access_token(
        data={"sub": user["username"], "role": user["role"], "name": user["full_name"]}
    )
    refresh_token = create_refresh_token(
        data={"sub": user["username"], "role": user["role"]}
    )
    await record_audit(
        db, action="auth.login", actor=user["username"], actor_role=user["role"],
        resource_type="session", detail="Credentials accepted",
        ip_address=_client_ip(request), request_id=request_id_of(request),
    )
    logger.info(f"Login successful: {req.username} (role={user['role']})")
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {
            "username": user["username"],
            "role": user["role"],
            "full_name": user["full_name"],
        },
        "expires_in_minutes": settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    }


@router.post("/auth/refresh", tags=["Authentication"])
async def refresh_token(req: RefreshRequest):
    """Exchange a refresh token for a new access token, rotating the refresh token.

    Previously this handed back only a new access token and let the caller keep
    reusing the same 7-day refresh token forever, so a single captured refresh
    token was a permanent credential. Now the presented token is denylisted as it
    is exchanged, and replaying it is refused.
    """
    payload = decode_token(req.token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if not payload.get("jti") or is_token_revoked(payload):
        raise HTTPException(status_code=401, detail="Refresh token has been revoked")

    # Re-read the identity from the user store instead of trusting the claims on a
    # token that may be weeks old (role changes, deletions).
    username = payload.get("sub")
    user = BUILTIN_USERS.get(username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    revoke_token(req.token)   # rotation: the presented token dies here
    new_access = create_access_token(
        data={"sub": user["username"], "role": user["role"], "name": user["full_name"]}
    )
    new_refresh = create_refresh_token(
        data={"sub": user["username"], "role": user["role"]}
    )
    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "expires_in_minutes": settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    }


@router.post("/auth/logout", tags=["Authentication"])
async def logout(
    request: Request,
    req: Optional[LogoutRequest] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Revoke the caller's access token (from the Authorization header) and, when
    supplied, the accompanying refresh token.

    Until now logout existed only in the frontend, which deleted localStorage: the
    tokens themselves stayed valid for their full lifetime for anyone who had
    captured them.
    """
    revoked: List[str] = []

    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        if token:
            revoke_token(token)
            revoked.append("access")

    if req and req.refresh_token:
        try:
            revoke_token(req.refresh_token)
            revoked.append("refresh")
        except HTTPException:
            # Already expired/invalid — logout must still succeed.
            logger.info("Logout: supplied refresh token was already invalid")

    await record_audit(
        db, action="auth.logout", actor=current_user.get("sub"),
        actor_role=current_user.get("role"), resource_type="session",
        detail=f"Revoked: {revoked or ['access']}",
        ip_address=_client_ip(request), request_id=request_id_of(request),
    )
    logger.info(f"Logout: {current_user.get('sub')} (revoked: {revoked or 'access'})")
    return {"status": "logged_out", "revoked": revoked}


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
    existing_target = existing.scalar_one_or_none()
    if existing_target:
        existing_target.updated_at = datetime.utcnow()
        if target.ip_address:
            existing_target.ip_address = target.ip_address
        if target.organization:
            existing_target.organization = target.organization
        await db.commit()
        await db.refresh(existing_target)
        return existing_target

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
    current_user: dict = Depends(require_roles("admin", "analyst")),
):
    """Delete a target (analyst+ role required)."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    snapshot = {
        "domain": target.domain,
        "ip_address": target.ip_address,
        "organization": target.organization,
    }

    # blocked_ips.threat_id is deliberately not an ORM cascade: a firewall rule
    # must not vanish because someone deleted the target that triggered it. With
    # SQLite foreign keys enforced, the reference has to be released by hand.
    await db.execute(
        update(BlockedIP)
        .where(BlockedIP.threat_id.in_(
            select(Threat.id).where(Threat.target_id == target_id)
        ))
        .values(threat_id=None)
    )

    await db.delete(target)
    await db.commit()

    await record_audit(
        db, action="target.delete",
        actor=current_user.get("sub"), actor_role=current_user.get("role"),
        resource_type="target", resource_id=target_id, detail="Target and its "
        "scans/threats/incidents deleted; related block rules detached, not removed",
        before_state=snapshot,
    )
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

    # Check if Nmap active scanning is requested
    nmap_enabled = getattr(request, 'nmap_enabled', False)
    nmap_scan_type = getattr(request, 'nmap_scan_type', 'standard')
    nmap_custom_ports = getattr(request, 'nmap_custom_ports', None)

    if nmap_enabled:
        if current_user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Active Nmap scanning requires admin privileges.")
        
        # Resolve target and check for private/internal IPs to prevent SSRF
        nmap_target = target.ip_address or target.domain
        try:
            # gethostbyname is a blocking call: it used to run straight on the event
            # loop, so every slow or hanging DNS lookup froze the dashboard, the
            # WebSocket broadcasts and every other request with it.
            # Resolved through the `socket` module attribute so tests can stub it.
            resolved_ip = await asyncio.to_thread(socket.gethostbyname, nmap_target)
            ip_obj = ipaddress.ip_address(resolved_ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_link_local:
                raise HTTPException(status_code=400, detail="Scanning internal, reserved, or loopback IPs is prohibited.")
        except socket.gaierror:
            raise HTTPException(status_code=400, detail=f"Could not resolve target hostname: {nmap_target}")

        # Validate the user-supplied scan spec before it reaches the Nmap CLI.
        # scan_type/ports/target are interpolated straight into the argument
        # string, so an unvalidated value is a command-injection primitive.
        validation_error = NmapService.validate_scan_inputs(
            resolved_ip, nmap_scan_type, nmap_custom_ports
        )
        if validation_error:
            raise HTTPException(status_code=400, detail=validation_error)

    scan_detail = "Running Shodan, VirusTotal, CVE/NVD, AlienVault OTX"
    if nmap_enabled:
        scan_detail += " + Nmap Active Scan"
    
    is_hybrid = nmap_enabled
    await ws_manager.broadcast_system_event(
        "info", f"{'Hybrid' if is_hybrid else 'OSINT'} scan started: {target.domain}",
        detail=scan_detail
    )

    osint_results = await OSINTAggregator.full_scan(target.domain, target.ip_address)

    # Run Nmap active scan if enabled and merge results
    if nmap_enabled:
        try:
            nmap_target = target.ip_address or target.domain
            await ws_manager.broadcast_system_event(
                "info", f"Nmap active scan running: {nmap_target}",
                detail=f"Scan type: {nmap_scan_type} — this may take 30-120 seconds"
            )
            nmap_results = await NmapService.scan(
                target=resolved_ip,
                scan_type=nmap_scan_type,
                ports=nmap_custom_ports,
            )
            osint_results = NmapService.merge_with_osint(nmap_results, osint_results)
            await ws_manager.broadcast_system_event(
                "success", f"Nmap scan completed: {nmap_target}",
                detail=f"{nmap_results.get('duration_seconds', 0):.1f}s | "
                       f"{len(nmap_results.get('open_ports', []))} ports | "
                       f"{len(nmap_results.get('vulnerabilities', []))} vulns"
            )
        except Exception as e:
            logger.error(f"Nmap scan failed for {target.domain}: {e}")
            osint_results["nmap"] = {"status": "error", "error": str(e)}



    # Determine scan type label based on which active scanners were used
    if nmap_enabled:
        scan_type_label = "hybrid_osint_nmap"
    else:
        scan_type_label = "full_osint"

    # Dynamically map ports and vulnerabilities based on scan type
    mapped_ports = osint_results.get("sources", {}).get("shodan", {}).get("ports", [])
    mapped_vulns = osint_results.get("sources", {}).get("shodan", {}).get("vulns", [])

    if nmap_enabled and osint_results.get("nmap", {}).get("status") == "completed":
        # Hybrid scan: merge Nmap and OSINT data
        nmap_data = osint_results["nmap"]
        mapped_ports = list(set(mapped_ports + [s.get("port") for s in nmap_data.get("services", [])]))
        for v in nmap_data.get("active_vulnerabilities", []):
            if v.get("cve_ids"):
                mapped_vulns.extend(v["cve_ids"])
            else:
                mapped_vulns.append(v.get("script", "nmap-vuln"))



    # De-duplicate
    mapped_ports = sorted(list(set(mapped_ports)))
    mapped_vulns = sorted(list(set(mapped_vulns)))

    # Fetch the most recent previous scan for this target.
    # NOTE: scalar_one_or_none() raises MultipleResultsFound as soon as a target
    # has more than one Scan row (e.g. after POST /scan/nmap), which 500s this
    # endpoint. There is no unique constraint on scans.target_id, so read the
    # latest row instead of assuming at most one exists.
    existing_scan = (await db.execute(
        select(Scan)
        .where(Scan.target_id == target.id)
        .order_by(Scan.started_at.desc())
        .limit(1)
    )).scalars().first()

    if existing_scan:
        scan = existing_scan
        scan.scan_type = scan_type_label
        scan.status = DBScanStatus.COMPLETED
        scan.results = osint_results
        scan.open_ports = mapped_ports
        scan.vulnerabilities = mapped_vulns
        scan.reputation_score = osint_results.get("risk_score")
        scan.completed_at = datetime.utcnow()
        scan.started_at = datetime.utcnow()  # Update started_at to reflect latest scan time
    else:
        scan = Scan(
            id=str(uuid.uuid4()),
            target_id=target.id,
            scan_type=scan_type_label,
            status=DBScanStatus.COMPLETED,
            results=osint_results,
            open_ports=mapped_ports,
            vulnerabilities=mapped_vulns,
            reputation_score=osint_results.get("risk_score"),
            completed_at=datetime.utcnow(),
            started_at=datetime.utcnow()
        )
        db.add(scan)

    threats_created = []

    # Fetch existing active threats to prevent duplicates
    existing_threats = (await db.execute(
        select(Threat.title).where(
            Threat.target_id == target.id,
            Threat.is_archived == False,
            Threat.is_resolved == False
        )
    )).scalars().all()
    existing_threat_titles = set(existing_threats)

    # 1. Map real vulnerabilities to Threats (Active & High/Critical OSINT)
    # Map Nmap active vulnerabilities
    if nmap_enabled and osint_results.get("nmap", {}).get("status") == "completed":
        for vuln in osint_results["nmap"].get("active_vulnerabilities", []):
            if vuln.get("severity") in ["HIGH", "CRITICAL"]:
                title = f"Active Vulnerability: {vuln.get('script')}"
                if title in existing_threat_titles:
                    continue
                sev_val = vuln["severity"].lower()
                cves = ", ".join(vuln.get("cve_ids", []))
                threat = Threat(
                    id=str(uuid.uuid4()),
                    target_id=target.id,
                    title=title,
                    description=f"Confirmed active by Nmap. CVEs: {cves}. {vuln.get('description', '')[:300]}",
                    severity=SeverityLevel(sev_val),
                    severity_score=9.8 if sev_val == "critical" else 7.5,
                    category="Exploitable Vulnerability",
                    mitre_tactic="Initial Access",
                    mitre_technique_name="Exploit Public-Facing Application",
                    ioc_value=cves if cves else vuln.get('script'),
                    source_latitude=osint_results.get("summary", {}).get("geolocation", {}).get("lat"),
                    source_longitude=osint_results.get("summary", {}).get("geolocation", {}).get("lon")
                )
                
                # Fetch custom remediation from LLM. The text is screened before it is
                # stored: it is model output derived partly from the scanned host's
                # own banners, and an analyst may paste it into a shell.
                enrichment = await LocalLLMService.generate_remediation_for_active_threat(
                    target.domain, threat.title, threat.description
                )
                screened, warnings = screen_remediation(enrichment.get("remediation", []))
                if warnings:
                    logger.warning(
                        "LLM remediation for %r: %s", threat.title, "; ".join(warnings)
                    )
                threat.root_cause = enrichment.get("root_cause")
                threat.attack_vector_detail = enrichment.get("attack_vector_detail")
                threat.remediation = screened

                db.add(threat)
                existing_threat_titles.add(threat.title)
                threats_created.append(threat.title)



    # Map High/Critical OSINT vulnerabilities
    for svc in osint_results.get("vulnerabilities_by_service", []):
        for cve in svc.get("cves", []):
            if cve.get("cvss_score", 0) >= 7.0:
                title = f"CVE Found: {cve.get('cve_id')} on {svc.get('service', 'Service')}"
                if title in existing_threat_titles:
                    continue
                sev_val = "critical" if cve.get("cvss_score", 0) >= 9.0 else "high"
                threat = Threat(
                    id=str(uuid.uuid4()),
                    target_id=target.id,
                    title=title,
                    description=f"{cve.get('description', '')[:300]} (CVSS: {cve.get('cvss_score')})",
                    severity=SeverityLevel(sev_val),
                    severity_score=cve.get("cvss_score"),
                    category="Known Vulnerability",
                    mitre_tactic="Initial Access",
                    mitre_technique_name="Exploit Public-Facing Application",
                    ioc_value=cve.get("cve_id"),
                )
                
                # Fetch custom remediation from LLM for high/critical active threats
                if sev_val in ["critical", "high"]:
                    enrichment = await LocalLLMService.generate_remediation_for_active_threat(
                        target.domain, threat.title, threat.description
                    )
                    screened, warnings = screen_remediation(enrichment.get("remediation", []))
                    if warnings:
                        logger.warning(
                            "LLM remediation for %r: %s", threat.title, "; ".join(warnings)
                        )
                    threat.root_cause = enrichment.get("root_cause")
                    threat.attack_vector_detail = enrichment.get("attack_vector_detail")
                    threat.remediation = screened
                    
                db.add(threat)
                existing_threat_titles.add(threat.title)
                threats_created.append(threat.title)



    # 2. Get Mathematical ML Predictions (Ensemble Layer)
    lstm_results = await LSTMPredictor.predict_threats(target.domain, osint_results)
    
    # Autoencoder expects generic dict if traffic_data is not available, 
    # but we will just pass a generic feature dict generated from the osint data for now.
    autoencoder_results = await AutoencoderDetector.detect_anomalies()

    # 3. Pass math outputs to LLM Triage (Integration Layer)
    predictions = await LocalLLMService.generate_prediction(
        target.domain, 
        osint_results, 
        lstm_results=lstm_results, 
        autoencoder_results=autoencoder_results
    )

    # ── Validate untrusted LLM output before it reaches the database ──────────
    # `pred["probability"]` raised KeyError mid-scan (after DB writes had already
    # begun) whenever the model omitted a field. Malformed entries are now dropped
    # with a log line instead of failing the scan, and percentages/floats are
    # normalised rather than rejected.
    validated_predictions = validate_predictions(predictions)
    if len(validated_predictions) != len(predictions):
        logger.warning(
            "Discarded %d malformed LLM prediction(s) out of %d",
            len(predictions) - len(validated_predictions), len(predictions),
        )
    predictions = validated_predictions

    for pred in predictions[:5]:
        if pred.get("probability", 0.0) > 0.5:
            title = f"Predicted: {pred.get('predicted_attack_type', 'Unknown Threat')}"
            if title in existing_threat_titles:
                continue
            mitre_mapping = MITREMapper.map_threat(
                pred.get("predicted_attack_type", ""),
                pred.get("predicted_attack_type", ""),
            )
            severity_result = SeverityScorer.calculate_score(
                cvss_base=pred.get("cvss_score", 5.0) or 5.0,
                exploit_likelihood=pred.get("probability", 0.0),
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
                title=title,
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
                remediation=screen_remediation(pred.get("remediation"))[0],
            )
            db.add(threat)
            existing_threat_titles.add(threat.title)
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

    from app.services.ml.ml_engine import MODELS_LOADED
    try:
        from app.services.ml.ml_engine import lstm_killchain_engine, ae_engine
        lstm_mocked = getattr(lstm_killchain_engine, 'is_mocked', False)
        ae_mocked = getattr(ae_engine, 'is_mocked', False)
    except ImportError:
        lstm_mocked = True
        ae_mocked = True

    model_metadata = {
        "models_loaded": MODELS_LOADED,
        "lstm_mocked": lstm_mocked,
        "ae_mocked": ae_mocked,
        "llm_available": await LocalLLMService.is_ollama_available()
    }

    # Telemetry: Log the scan to the custom ML dataset in the background
    background_tasks.add_task(
        TelemetryCollector.log_scan,
        target.domain,
        osint_results,
        lstm_results,
        autoencoder_results,
        predictions,
        model_metadata
    )

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
        "nmap": osint_results.get("nmap"),
    }


@router.post("/scan/nmap", tags=["Active Scanning"])
async def run_nmap_scan(
    target_id: str,
    scan_type: str = Query("standard", description="quick | standard | deep"),
    ports: Optional[str] = Query(None, description="Custom port range, e.g. '22,80,443' or '1-1024'"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_admin_role),
):
    """
    Run a standalone Nmap active scan against a target.
    Requires admin privileges. Returns raw Nmap results.
    Scan types:
      - quick: Top 100 ports + service detection (~10-20s)
      - standard: Top 1000 ports + service + OS detection (~30-60s)
      - deep: All ports + NSE vulnerability scripts (~60-180s)
    """
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    nmap_target = target.ip_address or target.domain

    # Reject hostile scan parameters before they are interpolated into the Nmap
    # command line (see NmapService.validate_scan_inputs). Done here as well as in
    # the service so the client gets a 400 instead of a 500.
    validation_error = NmapService.validate_scan_inputs(nmap_target, scan_type, ports)
    if validation_error:
        raise HTTPException(status_code=400, detail=validation_error)

    await ws_manager.broadcast_system_event(
        "info", f"Nmap {scan_type} scan initiated: {nmap_target}",
        detail=f"Admin: {current_user.get('sub')} | Ports: {ports or 'auto'}"
    )

    nmap_results = await NmapService.scan(
        target=nmap_target,
        scan_type=scan_type,
        ports=ports,
    )

    if nmap_results.get("status") == "error":
        await ws_manager.broadcast_system_event(
            "error", f"Nmap scan failed: {nmap_target}",
            detail=nmap_results.get("error", "Unknown error")
        )
        raise HTTPException(status_code=500, detail=nmap_results.get("error", "Nmap scan failed"))

    # Save as a scan record
    scan = Scan(
        id=str(uuid.uuid4()),
        target_id=target.id,
        scan_type=f"nmap_{scan_type}",
        status=DBScanStatus.COMPLETED,
        results=nmap_results,
        open_ports=nmap_results.get("open_ports", []),
        vulnerabilities=[v.get("description", "")[:200] for v in nmap_results.get("vulnerabilities", [])],
        completed_at=datetime.utcnow(),
    )
    db.add(scan)
    await db.commit()

    await ws_manager.broadcast_system_event(
        "success", f"Nmap scan completed: {nmap_target}",
        detail=f"{nmap_results.get('duration_seconds', 0)}s | "
               f"{len(nmap_results.get('open_ports', []))} ports | "
               f"{len(nmap_results.get('services', []))} services | "
               f"{len(nmap_results.get('vulnerabilities', []))} vulns"
    )

    return {
        "scan_id": scan.id,
        "target": target.domain,
        **nmap_results,
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
    """Check the status of the local LLM Engine (Llama 3) and native ML models."""
    is_up = await LocalLLMService.is_ollama_available()
    model_status = get_model_status()
    # `ml_inference_is_real` is False whenever any engine fell back to fabricated
    # weights, so a green "online" status can no longer imply real inference.
    base = {
        "ml_inference_is_real": model_status["models_loaded"],
        "models": model_status,
    }
    if is_up:
        return {**base, "status": "online", "engine": "Llama 3 8B (LoRA)", "message": "Connected to local Ollama API."}
    return {**base, "status": "offline", "engine": "LSTMPredictor / AutoencoderDetector", "message": "Ollama LLM unreachable. Using simulated statistical fallback."}

@router.post("/ml/predict", tags=["AI/ML Engine"])
async def predict_threats(
    domain: str,
    current_user: dict = Depends(check_admin_role),
):
    """Run Llama 3 threat prediction for a domain."""
    # Use real OSINT scanner for live data
    osint_results = await OSINTAggregator.full_scan(domain, "")
    
    # Compute Ensemble Context
    lstm_results = await LSTMPredictor.predict_threats(domain, osint_results)
    autoencoder_results = await AutoencoderDetector.detect_anomalies()
    
    # Pass to LLM
    predictions = await LocalLLMService.generate_prediction(
        domain, 
        osint_results,
        lstm_results=lstm_results,
        autoencoder_results=autoencoder_results
    )

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
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_admin_role),
):
    """Run LLM/autoencoder anomaly detection against the local host.

    Two things this endpoint used to do that it must not:

    * it ignored `threshold` entirely — accepted it, echoed it back, applied nothing;
    * it filed a CRITICAL Incident for any score > 0.9, which meant an *invented*
      attacker IP (the LLM is asked to "generate 3 realistic anomalies", and the
      autoencoder path fabricates its flow inventory) became a real incident that
      /soar/block-ip would happily act on.

    Escalation now requires evidence that was not fabricated, and every record is
    labelled with its provenance.
    """
    if not 0.0 <= threshold <= 1.0:
        raise HTTPException(status_code=400, detail="threshold must be between 0.0 and 1.0")

    results = await LocalLLMService.detect_anomalies()
    anomalies = results.get("anomalies", [])

    # Apply the threshold the caller asked for (previously accepted and ignored).
    anomalies = [
        a for a in anomalies if float(a.get("anomaly_score", 0.0) or 0.0) >= threshold
    ]

    escalated = 0
    simulated = 0

    for anomaly in anomalies:
        dna = ThreatDNAFingerprinter.generate_fingerprint({"type": anomaly["classification"]})
        anomaly["threat_dna"] = dna

        # Provenance is explicit: only a record that positively identifies itself as
        # real inference is eligible to become an incident.
        evidence_source = anomaly.get("evidence_source")
        is_simulated = anomaly.get("is_simulated", True) or evidence_source in (
            "simulation", "llm_generated", None,
        )
        if is_simulated:
            simulated += 1

        score = float(anomaly.get("anomaly_score", 0.0) or 0.0)
        anomaly["escalated"] = bool(not is_simulated and score > 0.9)

        # Save to AnomalyDetection table. Provenance travels inside the JSON
        # `features` column: AnomalyDetection has no dedicated column for it, and
        # adding one would need a migration (create_all() cannot ALTER an existing
        # table), so the row stays self-describing without breaking existing DBs.
        features = dict(anomaly.get("features") or {})
        features["_provenance"] = {
            "evidence_source": evidence_source or "unknown",
            "is_simulated": bool(is_simulated),
            "synthetic_flow_inventory": bool(anomaly.get("synthetic_flow_inventory", True)),
        }
        anomaly_record = AnomalyDetection(
            source_ip=anomaly.get("source_ip"),
            destination_ip=anomaly.get("destination_ip"),
            anomaly_score=anomaly.get("anomaly_score", 0.0),
            is_anomalous=anomaly.get("is_anomalous", True),
            features=features,
            reconstruction_error=anomaly.get("reconstruction_error"),
            pattern_fingerprint=dna.get("fingerprint") if isinstance(dna, dict) else dna
        )
        db.add(anomaly_record)

        # Create an Incident only for non-simulated evidence above the threshold.
        if anomaly["escalated"]:
            escalated += 1
            inc = Incident(
                title=f"Critical Anomaly: {anomaly['classification']}",
                description=(
                    f"Autoencoder detected a highly anomalous pattern from "
                    f"{anomaly['source_ip']} (score: {anomaly['anomaly_score']}, "
                    f"threshold: {threshold})."
                ),
                severity="critical",
                status="open",
                source="ml_anomaly"
            )
            db.add(inc)
    await db.commit()

    return {
        "anomalies_detected": len(anomalies),
        "threshold": threshold,
        "escalated_incidents": escalated,
        "simulated_count": simulated,
        "evidence_basis": results.get("evidence_basis", "autoencoder_simulation"),
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
    current_user: dict = Depends(require_roles("admin", "analyst")),
):
    """Create a new incident with auto-generated response playbook."""
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
    # Also exclude AI predictions (title starts with 'Predicted:') from active threat counts.
    threats_count = (await db.execute(
        select(func.count(Threat.id)).where(
            and_(Threat.is_resolved == False, Threat.is_archived == False, ~Threat.title.like('Predicted:%'))
        )
    )).scalar() or 0
    critical_count = (await db.execute(
        select(func.count(Threat.id)).where(
            and_(Threat.severity == SeverityLevel.CRITICAL, Threat.is_resolved == False, Threat.is_archived == False, ~Threat.title.like('Predicted:%'))
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
    # Exclude AI predictions from dashboard aggregations — they have their own tab
    all_threats_result = await db.execute(
        select(Threat).options(selectinload(Threat.target)).where(
            and_(Threat.is_archived == False, ~Threat.title.like('Predicted:%'))
        ).order_by(Threat.detected_at.desc()).limit(1000)
    )
    all_active_threats = all_threats_result.scalars().all()
    recent_threats = all_active_threats[:50]

    recent_incidents_result = await db.execute(
        select(Incident).where(Incident.is_archived == False).order_by(Incident.detected_at.desc()).limit(10)
    )
    recent_incidents = recent_incidents_result.scalars().all()

    severity_counts = {}
    for sev in SeverityLevel:
        count = (await db.execute(
            select(func.count(Threat.id)).where(and_(Threat.severity == sev, Threat.is_archived == False, ~Threat.title.like('Predicted:%')))
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

    await record_audit(
        db, action="system.new_session",
        actor=current_user.get("sub"), actor_role=current_user.get("role"),
        resource_type="system",
        detail="Active targets/scans/threats/incidents/anomalies archived",
    )
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
    http_request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_admin_role),
):
    """
    Permanently delete ALL targets, scans, threats, and incidents from the database.
    This allows users to do a fresh re-scan of domains.

    Active firewall block rules survive on purpose. "Wipe the demo data" is not a
    request to start accepting traffic from every IP an analyst had blocked, so the
    rules are kept and only their threat references are released.
    """
    from sqlalchemy import delete as sql_delete

    # Record what is about to disappear, so the audit row is useful on its own.
    # Separate scalar counts: selecting several count()s over different tables in
    # one statement would cross-join them and report inflated numbers.
    deleted_summary = {
        "targets": (await db.execute(select(func.count(Target.id)))).scalar() or 0,
        "scans": (await db.execute(select(func.count(Scan.id)))).scalar() or 0,
        "threats": (await db.execute(select(func.count(Threat.id)))).scalar() or 0,
        "incidents": (await db.execute(select(func.count(Incident.id)))).scalar() or 0,
    }

    # Release block-rule references before dropping threats: blocked_ips.threat_id
    # is a real foreign key now that SQLite enforcement is on.
    await db.execute(update(BlockedIP).values(threat_id=None))

    # Delete in dependency order to respect foreign keys
    await db.execute(sql_delete(ThreatPrediction))
    await db.execute(sql_delete(AnomalyDetection))
    await db.execute(sql_delete(RemediationLog))
    await db.execute(sql_delete(OSINTData))
    # Incident.threat_id references threats.id, so incidents must be removed
    # BEFORE threats regardless of SQLite only enforcing FKs when the pragma is
    # enabled — the previous Threat-before-Incident order only worked because
    # SQLite skips FK enforcement by default.
    await db.execute(sql_delete(Incident))
    await db.execute(sql_delete(Threat))
    await db.execute(sql_delete(Scan))
    await db.execute(sql_delete(Target))
    await db.commit()

    await record_audit(
        db, action="history.delete_all",
        actor=current_user.get("sub"), actor_role=current_user.get("role"),
        resource_type="history",
        detail=f"Permanently deleted history: {deleted_summary}. "
               "Active firewall block rules were preserved.",
        ip_address=_client_ip(http_request), request_id=request_id_of(http_request),
        before_state=deleted_summary,
    )
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

# Firewall rules live in the `blocked_ips` table, not in a module-level dict.
# The dict meant a backend restart silently emptied the "firewall" while dashboards
# still showed the old rules, so an operator could reasonably believe a hostile IP
# was being dropped when nothing was. Multi-worker uvicorn also gave each process
# its own copy of the dict.
class SOARBlockRequest(BaseModel):
    ip: str
    threat_id: Optional[str] = None
    reason: Optional[str] = "Blocked via ITAP SOC Dashboard"


def _block_rule_dict(rule: BlockedIP) -> Dict[str, Any]:
    """Wire shape kept identical to the old dict so the UI needs no change."""
    return {
        "ip": rule.ip_address,
        "rule_id": rule.rule_id,
        "reason": rule.reason,
        "blocked_by": rule.blocked_by,
        "blocked_at": rule.blocked_at.isoformat() if rule.blocked_at else None,
        "threat_id": rule.threat_id,
    }


def _firewall_command(ip: str, rule_id: str) -> str:
    """The command an operator would run for real. ITAP never executes it."""
    tool = "ip6tables" if ":" in ip else "iptables"
    return f"{tool} -A INPUT -s {ip} -j DROP  # {rule_id}"


@router.post("/soar/block-ip", tags=["SOAR"])
async def soar_block_ip(
    request: SOARBlockRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_admin_role),
):
    """
    [ADMIN ONLY] Block a malicious IP via the mock firewall integration.
    In production, replace the mock store with a real firewall API call.

    Validation uses ``ipaddress`` rather than the previous ``^(\\d{1,3}\\.){3}\\d{1,3}$``
    regex: that regex accepted 999.1.1.1 and rejected every IPv6 address, including
    the IPv6 addresses the anomaly detector reports.
    """
    try:
        ip = str(ipaddress.ip_address(request.ip.strip()))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    existing = (await db.execute(
        select(BlockedIP).where(BlockedIP.ip_address == ip)
    )).scalar_one_or_none()
    if existing is not None and existing.status == "active":
        # Idempotent: double-clicking "block" must not mint a second rule for the
        # same address, nor claim a fresh action happened.
        return {
            "status": "already_blocked",
            "ip": ip,
            "rule_id": existing.rule_id,
            "message": f"IP {ip} was already blocked by rule {existing.rule_id}.",
            "mock_command": _firewall_command(ip, existing.rule_id),
        }

    if existing is not None:
        # ip_address is unique: one row per address holding its current state, while
        # the block/unblock history lives in the audit trail. Reusing the row keeps
        # re-blocking an IP that was released earlier from violating the constraint.
        rule = existing
        rule.rule_id = f"ITAP-{uuid.uuid4().hex[:8].upper()}"
        rule.reason = request.reason
        rule.blocked_by = current_user.get("sub", "admin")
        rule.blocked_at = datetime.utcnow()
        rule.released_at = None
        rule.status = "active"
        rule.threat_id = request.threat_id
    else:
        rule = BlockedIP(
            id=str(uuid.uuid4()),
            ip_address=ip,
            rule_id=f"ITAP-{uuid.uuid4().hex[:8].upper()}",
            reason=request.reason,
            blocked_by=current_user.get("sub", "admin"),
            blocked_at=datetime.utcnow(),
            status="active",
            threat_id=request.threat_id,
        )
        db.add(rule)

    # Update the linked threat status if provided
    if request.threat_id:
        threat = (await db.execute(select(Threat).where(Threat.id == request.threat_id))).scalar_one_or_none()
        if threat:
            threat.is_resolved = True
            threat.resolved_at = datetime.utcnow()

    await db.commit()
    await db.refresh(rule)

    await record_audit(
        db, action="ip.block",
        actor=current_user.get("sub"), actor_role=current_user.get("role"),
        resource_type="blocked_ip", resource_id=rule.rule_id,
        detail=f"Blocked {ip}. Reason: {request.reason}",
        ip_address=_client_ip(http_request), request_id=request_id_of(http_request),
        after_state=_block_rule_dict(rule),
    )
    await ws_manager.broadcast_system_event(
        "warning", f"IP Blocked: {ip}",
        detail=f"Firewall rule {rule.rule_id} applied by {current_user.get('sub', 'admin')}. Reason: {request.reason}"
    )

    return {
        "status": "blocked",
        "ip": ip,
        "rule_id": rule.rule_id,
        "message": f"IP {ip} has been blocked. Firewall rule {rule.rule_id} is active.",
        "mock_command": _firewall_command(ip, rule.rule_id),
    }


@router.get("/soar/blocked-ips", tags=["SOAR"])
async def soar_get_blocked_ips(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get all currently blocked IPs and their firewall rules."""
    rules = (await db.execute(
        select(BlockedIP).where(BlockedIP.status == "active")
        .order_by(BlockedIP.blocked_at.desc())
    )).scalars().all()
    return {
        "count": len(rules),
        "blocked_ips": [_block_rule_dict(r) for r in rules],
    }


@router.delete("/soar/blocked-ips/{ip}", tags=["SOAR"])
async def soar_unblock_ip(
    ip: str,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_admin_role),
):
    """[ADMIN ONLY] Release a firewall block rule for a specific IP.

    The row is kept with status "released" rather than deleted: "who unblocked this,
    and when" is exactly the question an audit trail exists to answer.
    """
    try:
        canonical = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    rule = (await db.execute(
        select(BlockedIP).where(BlockedIP.ip_address == canonical, BlockedIP.status == "active")
    )).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail=f"IP {canonical} is not in the block list")

    rule_id = rule.rule_id
    rule.status = "released"
    rule.released_at = datetime.utcnow()
    await db.commit()

    await record_audit(
        db, action="ip.unblock",
        actor=current_user.get("sub"), actor_role=current_user.get("role"),
        resource_type="blocked_ip", resource_id=rule_id,
        detail=f"Released block on {canonical}",
        ip_address=_client_ip(http_request), request_id=request_id_of(http_request),
        before_state={"status": "active"}, after_state={"status": "released"},
    )
    await ws_manager.broadcast_system_event(
        "info", f"IP Unblocked: {canonical}",
        detail=f"Firewall rule {rule_id} removed by {current_user.get('sub', 'admin')}"
    )
    return {"status": "unblocked", "ip": canonical, "rule_id": rule_id}


# ─────────────────────────────────────────────────────────────────
# Platform audit trail
# ─────────────────────────────────────────────────────────────────

@router.get("/system/audit-log", tags=["System"])
async def get_audit_log(
    limit: int = Query(100, ge=1, le=1000),
    actor: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    outcome: Optional[str] = Query(None),
    since_days: Optional[int] = Query(None, ge=1, le=3650),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_admin_role),
):
    """
    [ADMIN ONLY] Read the append-only trail of privileged platform actions.

    Admin-only and read-only on purpose. The trail is the evidence an investigator
    relies on *after* an operator has been locked out, so an analyst role must not be
    able to read it selectively, and no role can edit it: there is no DELETE here.
    Retention/pruning is a deployment concern, not an endpoint.
    """
    rows = await audit_trail(
        db, limit=limit, actor=actor, action=action, outcome=outcome,
        since_days=since_days,
    )
    return {
        "count": len(rows),
        "total_rows": await audit_count(db),
        "entries": [
            {
                "id": r.id,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "actor": r.actor,
                "actor_role": r.actor_role,
                "action": r.action,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "outcome": r.outcome,
                "detail": r.detail,
                "ip_address": r.ip_address,
                "request_id": r.request_id,
                "before_state": r.before_state,
                "after_state": r.after_state,
            }
            for r in rows
        ],
    }
