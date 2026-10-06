"""
ITAP — platform audit trail.

A SOC product that cannot answer "who blocked this IP, when, from where, and did
it succeed" is not much of a SOC product. Before this existed the only audit-ish
table was RemediationLog (incident remediation), while the actions that actually
change ITAP's own posture — blocking an IP, wiping all history, starting a new
session, deleting a target, failed logins — were written to the console logger and
lost on restart.

Two rules shape this module:

* **An audit failure must never break the action it is recording.** Every write is
  wrapped in a SAVEPOINT and swallowed at ERROR level. Failing the operator's block
  rule because the audit insert had a problem would be worse than no audit row.
* **No secrets in `detail`.** Callers pass human-readable text; tokens, passwords
  and API keys are scrubbed defensively here as well.
"""
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import AuditLog

logger = logging.getLogger("itap.audit")

# Defensive scrub for the free-text column: an audit row that leaks a bearer token
# turns the audit trail into the thing that needs protecting.
_SCRUB_MARKERS = ("bearer ", "password", "api_key", "apikey", "token=")


def _clean(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    lowered = text.lower()
    if any(marker in lowered for marker in _SCRUB_MARKERS):
        return "[redacted — suspected credential]"
    return text[:2000]


def client_ip(request) -> str:
    """Best-effort client address, honouring a reverse proxy's X-Forwarded-For."""
    if request is None:
        return "unknown"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = getattr(request, "client", None)
    return client.host if client else "unknown"


def request_id_of(request) -> Optional[str]:
    """The X-Request-ID RequestIDMiddleware attached, so log lines and DB rows join."""
    if request is None:
        return None
    return getattr(getattr(request, "state", None), "request_id", None)


async def record_audit(
    db: Optional[AsyncSession],
    *,
    action: str,
    actor: Optional[str] = None,
    actor_role: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    outcome: str = "success",
    detail: Optional[str] = None,
    ip_address: Optional[str] = None,
    request_id: Optional[str] = None,
    before_state: Optional[Dict[str, Any]] = None,
    after_state: Optional[Dict[str, Any]] = None,
    commit: bool = True,
) -> Optional[AuditLog]:
    """Persist one append-only audit row. Returns the row, or None on failure.

    ``db`` is the caller's session so the row lands in the same database the action
    touched (and, in tests, in the fixture DB rather than the production file). Pass
    ``None`` only from non-request contexts; a standalone session is then opened off
    the application factory, looked up at call time so it stays patchable.

    ``commit=False`` keeps the row on the caller's transaction instead, for actions
    that must not be recorded unless the caller's own commit succeeds.
    """
    row = AuditLog(
        actor=actor or "anonymous",
        actor_role=actor_role,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        outcome=outcome,
        detail=_clean(detail),
        ip_address=ip_address,
        request_id=request_id,
        before_state=before_state,
        after_state=after_state,
    )

    try:
        if db is None:
            from app.db.database import async_session_factory

            async with async_session_factory() as session:
                session.add(row)
                await session.commit()
                return row

        # SAVEPOINT: a failed insert rolls back only the audit row, leaving the
        # caller's transaction usable.
        async with db.begin_nested():
            db.add(row)
        if commit:
            await db.commit()
        return row
    except Exception:
        logger.error(
            "AUDIT WRITE FAILED action=%s actor=%s outcome=%s",
            action, actor, outcome, exc_info=True,
        )
        return None


async def audit_trail(
    db: AsyncSession,
    *,
    limit: int = 100,
    actor: Optional[str] = None,
    action: Optional[str] = None,
    outcome: Optional[str] = None,
    since_days: Optional[int] = None,
) -> List[AuditLog]:
    """Read the trail back, newest first, with the usual filters applied in SQL."""
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome)
    if since_days:
        stmt = stmt.where(
            AuditLog.created_at >= datetime.utcnow() - timedelta(days=since_days)
        )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def audit_count(db: AsyncSession) -> int:
    return (await db.execute(select(func.count(AuditLog.id)))).scalar() or 0
