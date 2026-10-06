"""
ITAP — platform audit trail and persisted response state.

Two classes of bug are pinned here, and they are related:

* **Undocumented privilege use.** Blocking an IP, wiping all history, archiving a
  session, deleting a target and failing to log in used to exist only as a line in
  the console log. Nothing answered "who did this, from where, and did it succeed"
  once the process restarted — or at all, if nobody was watching stdout.
* **State that lied.** SOAR firewall rules lived in a module-level dict, so a restart
  emptied the "firewall" while a dashboard still showed the old rules, and each
  uvicorn worker had its own copy. Rules now live in the ``blocked_ips`` table.

Audit rows are deliberately *not* read back through the ORM the endpoints use: they
are read over a plain ``sqlite3`` connection, so a test cannot pass just because the
same buggy mapping both wrote and read the row.
"""
from datetime import datetime, timedelta

import pytest
from sqlalchemy import event, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core import security
from app.core.config import settings
from app.models.models import (
    AuditLog, BlockedIP, Incident, IncidentStatus, SeverityLevel, Target, Threat,
)
from app.services.audit_service import _clean, audit_count, audit_trail, record_audit

# Only exists when the configured URL is SQLite, which is what the suite runs on
# (conftest redirects DATABASE_URL to a throwaway file). Import it defensively so
# pointing the suite at PostgreSQL is a skip, not a collection error.
try:
    from app.db.database import _apply_sqlite_pragmas
except ImportError:  # pragma: no cover - only when pointed at PostgreSQL
    _apply_sqlite_pragmas = None

API = "/api/v1"


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    """Failed-login counters are process-global; this module hammers /auth/login."""
    def _clear():
        with security._FAILED_LOGINS_LOCK:
            security._FAILED_LOGINS.clear()

    _clear()
    yield
    _clear()


@pytest.fixture
def rows(raw_db):
    """Audit rows as plain dicts, oldest first."""
    def _rows(action: str | None = None):
        sql = "SELECT * FROM audit_logs"
        args: tuple = ()
        if action:
            sql += " WHERE action = ?"
            args = (action,)
        sql += " ORDER BY created_at"
        return [dict(r) for r in raw_db.execute(sql, args)]

    return _rows


@pytest.fixture
async def seed(test_db_path):
    """
    An ORM session on the per-test database, opened in the test's own event loop.

    Used to arrange state an endpoint cannot cleanly create (a block rule pointing at
    a threat, a row aged into the past). The same connection pragmas apply, so these
    writes really are subject to the same foreign key rules as the request path.
    """
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{test_db_path.as_posix()}",
        echo=False,
        poolclass=NullPool,
    )
    if _apply_sqlite_pragmas is not None:
        event.listen(engine.sync_engine, "connect", _apply_sqlite_pragmas)
    Session = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    async with Session() as session:
        yield session

    engine.sync_engine.dispose()




# ─────────────────────────────────────────────────────────────────────────────
# C11 — authentication is recorded
# ─────────────────────────────────────────────────────────────────────────────
def test_successful_login_is_audited(client, rows):
    client.post(
        f"{API}/auth/login",
        json={"username": "admin", "password": settings.ADMIN_PASSWORD},
    )

    logged = rows("auth.login")
    assert len(logged) == 1
    assert logged[0]["actor"] == "admin"
    assert logged[0]["actor_role"] == "admin"
    assert logged[0]["outcome"] == "success"
    assert logged[0]["ip_address"], "a login with no source address is uninvestigable"


def test_failed_login_is_audited_and_leaks_no_credential(client, rows):
    client.post(
        f"{API}/auth/login",
        json={"username": "admin", "password": "hunter2-but-wrong"},
    )

    failures = rows("auth.login.failure")
    assert len(failures) == 1
    # The attempted username is recorded on purpose: repeated failures against one
    # account is what a password-guessing campaign looks like.
    assert failures[0]["actor"] == "admin"
    assert failures[0]["outcome"] == "failure"

    # ...but nothing that helps an attacker who can read the audit trail does.
    dumped = " ".join(
        str(value) for row in rows() for value in row.values() if value is not None
    )
    assert "hunter2-but-wrong" not in dumped


def test_throttled_login_attempts_are_audited(client, rows):
    payload = {"username": "admin", "password": "nope"}
    for _ in range(security.LOGIN_MAX_ATTEMPTS):
        client.post(f"{API}/auth/login", json=payload)

    assert client.post(f"{API}/auth/login", json=payload).status_code == 429

    denied = rows("auth.login.throttled")
    assert len(denied) == 1
    assert denied[0]["outcome"] == "denied"


def test_logout_is_audited(client, admin_headers, rows):
    assert client.post(f"{API}/auth/logout", headers=admin_headers).status_code == 200
    assert rows("auth.logout")[0]["actor"] == "admin"


# ─────────────────────────────────────────────────────────────────────────────
# C11 — who may read the trail
# ─────────────────────────────────────────────────────────────────────────────
def test_audit_log_requires_admin(client, analyst_headers, viewer_headers):
    """
    The trail is what you read to investigate an operator, so an analyst-role
    account must not be able to see and pick through what is recorded on it.
    """
    assert client.get(f"{API}/system/audit-log").status_code == 401
    assert client.get(f"{API}/system/audit-log", headers=analyst_headers).status_code == 403
    assert client.get(f"{API}/system/audit-log", headers=viewer_headers).status_code == 403


def test_admin_reads_and_filters_the_trail(client, admin_headers):
    client.post(
        f"{API}/auth/login",
        json={"username": "admin", "password": settings.ADMIN_PASSWORD},
    )
    client.post(f"{API}/auth/login", json={"username": "ghost", "password": "wrong"})

    body = client.get(f"{API}/system/audit-log", headers=admin_headers).json()
    assert {e["action"] for e in body["entries"]} >= {"auth.login", "auth.login.failure"}
    assert body["total_rows"] == body["count"] == 2

    only_failures = client.get(
        f"{API}/system/audit-log?outcome=failure", headers=admin_headers
    ).json()
    assert [e["action"] for e in only_failures["entries"]] == ["auth.login.failure"]

    by_actor = client.get(
        f"{API}/system/audit-log?actor=ghost", headers=admin_headers
    ).json()
    assert by_actor["count"] == 1 and by_actor["total_rows"] == 2


def test_there_is_no_route_that_edits_the_trail(client, admin_headers):
    """Append-only means append-only: no mutation route may exist for audit rows."""
    for method in ("delete", "put", "patch"):
        response = getattr(client, method)(
            f"{API}/system/audit-log", headers=admin_headers
        )
        assert response.status_code == 405, method


# ─────────────────────────────────────────────────────────────────────────────
# Audit service internals
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "raw",
    [
        "reason: Bearer eyJhbGciOiJIUzI1NiJ9.abc",
        "password=correct horse",
        "shodan api_key=deadbeef",
    ],
)
def test_credential_looking_detail_is_redacted(raw):
    assert _clean(raw) == "[redacted — suspected credential]"


def test_ordinary_detail_survives_untouched():
    assert _clean("Blocked 203.0.113.9. Reason: brute force") == (
        "Blocked 203.0.113.9. Reason: brute force"
    )


async def test_audit_write_failure_does_not_break_the_action(caplog):
    """
    The audit insert here fails for the mundane reason that the table is missing.

    What matters is the shape of the recovery: the caller's action still succeeds,
    the savepoint leaves its transaction usable, and an operator hears about the gap
    at ERROR level. Swallowing audit failures silently would leave a SOC believing it
    had an audit trail that was not being written.
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=NullPool)
    Session = async_sessionmaker(bind=engine, expire_on_commit=False)

    async with Session() as session:
        with caplog.at_level("ERROR", logger="itap.audit"):
            row = await record_audit(session, action="ip.block", actor="admin")

        assert row is None, "the caller must be able to tell the write was lost"
        assert "AUDIT WRITE FAILED" in caplog.text

        # The caller's transaction was not poisoned by the rolled-back savepoint.
        assert (await session.execute(select(1))).fetchone()[0] == 1

    engine.sync_engine.dispose()


async def test_audit_trail_age_filter_excludes_old_rows(seed):
    """The age filter belongs in SQL, and must really exclude rows outside the window."""
    seed.add(AuditLog(
        actor="admin", action="ip.block", outcome="success",
        created_at=datetime.utcnow() - timedelta(days=30),
    ))
    await seed.commit()

    assert await record_audit(seed, action="ip.unblock", actor="admin") is not None
    assert await audit_count(seed) == 2

    recent = await audit_trail(seed, limit=10, since_days=7)
    assert [r.action for r in recent] == ["ip.unblock"]

    both = await audit_trail(seed, limit=10, since_days=60)
    assert [r.action for r in both] == ["ip.unblock", "ip.block"]


# ─────────────────────────────────────────────────────────────────────────────
# C12 — SOAR block rules are persisted state, not process memory
# ─────────────────────────────────────────────────────────────────────────────
def block(client, headers, ip: str, **extra):
    return client.post(f"{API}/soar/block-ip", json={"ip": ip, **extra}, headers=headers)


def test_blocking_persists_the_rule_and_the_decision(client, admin_headers, raw_db):
    response = block(
        client, admin_headers, "203.0.113.9", reason="brute force against VPN"
    )
    assert response.status_code == 200
    assert response.json()["status"] == "blocked"

    stored = [dict(r) for r in raw_db.execute(
        "SELECT ip_address, reason, blocked_by, status FROM blocked_ips"
    )]
    assert stored == [{
        "ip_address": "203.0.113.9",
        "reason": "brute force against VPN",
        "blocked_by": "admin",
        "status": "active",
    }], "the firewall's state must be readable without going through the API"

    assert [dict(r) for r in raw_db.execute(
        "SELECT action, outcome, actor FROM audit_logs WHERE action = 'ip.block'"
    )] == [{"action": "ip.block", "outcome": "success", "actor": "admin"}]


def test_a_block_rule_outlives_the_process_that_made_it(
    client, make_client, admin_headers, test_db_path
):
    """
    Two clients over one file: a restarted backend reports the rules it blocked before.

    This is precisely what the module-level dict could never do, and it is why the
    dashboard may now claim a hostile address is being dropped.
    """
    assert block(client, admin_headers, "198.51.100.7").status_code == 200

    restarted = make_client(test_db_path)
    listed = restarted.get(
        f"{API}/soar/blocked-ips", headers=admin_headers
    ).json()["blocked_ips"]
    assert [e["ip"] for e in listed] == ["198.51.100.7"]
    assert listed[0]["reason"] == "Blocked via ITAP SOC Dashboard"


def test_blocking_the_same_ip_twice_reports_the_first_rule(
    client, admin_headers, raw_db
):
    first = block(client, admin_headers, "203.0.113.30")
    second = block(client, admin_headers, "203.0.113.30")

    assert second.json()["status"] == "already_blocked"
    assert second.json()["rule_id"] == first.json()["rule_id"]
    assert raw_db.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0] == 1
    assert raw_db.execute("SELECT COUNT(*) FROM audit_logs WHERE action='ip.block'").fetchone()[0] == 1


def test_releasing_and_reblocking_reuses_the_row(client, admin_headers, raw_db):
    """
    ``ip_address`` is unique, so a released rule has to be revived, not re-inserted.

    A plain INSERT would raise IntegrityError the second time an analyst blocks an
    address they released earlier — a 500 for the most ordinary sequence in the UI.
    """
    assert block(client, admin_headers, "203.0.113.31").status_code == 200
    assert client.delete(
        f"{API}/soar/blocked-ips/203.0.113.31", headers=admin_headers
    ).status_code == 200
    assert raw_db.execute(
        "SELECT status FROM blocked_ips WHERE ip_address='203.0.113.31'"
    ).fetchone()[0] == "released"

    assert block(client, admin_headers, "203.0.113.31").status_code == 200
    assert raw_db.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0] == 1
    assert raw_db.execute(
        "SELECT status, released_at FROM blocked_ips WHERE ip_address='203.0.113.31'"
    ).fetchone()[:] == ("active", None)


def test_releasing_a_rule_keeps_it_as_history(client, admin_headers, raw_db):
    block(client, admin_headers, "203.0.113.32")
    assert client.delete(
        f"{API}/soar/blocked-ips/203.0.113.32", headers=admin_headers
    ).status_code == 200

    assert client.get(
        f"{API}/soar/blocked-ips", headers=admin_headers
    ).json()["blocked_ips"] == []
    # The row survives: "we blocked this on Monday and released it on Tuesday" is the
    # question asked after an incident closes, and nothing else can answer it.
    assert raw_db.execute(
        "SELECT status FROM blocked_ips WHERE ip_address='203.0.113.32'"
    ).fetchone()[0] == "released"
    assert raw_db.execute(
        "SELECT outcome FROM audit_logs WHERE action='ip.unblock'"
    ).fetchone()[0] == "success"


def test_ipv6_is_a_valid_block_target(client, admin_headers):
    """A validator that rejects IPv6 guarantees IPv6 traffic is never blocked."""
    assert block(client, admin_headers, "2001:db8::1337").status_code == 200
    listed = client.get(f"{API}/soar/blocked-ips", headers=admin_headers).json()
    assert [e["ip"] for e in listed["blocked_ips"]] == ["2001:db8::1337"]


@pytest.mark.parametrize("bad", ["not-an-ip", "999.1.1.1", "203.0.113.9.1", "", "203.0.113.9/32"])
def test_malformed_addresses_are_refused_before_they_reach_the_firewall(
    client, admin_headers, bad
):
    assert block(client, admin_headers, bad).status_code == 400


def test_viewer_cannot_change_the_firewall(client, viewer_headers, raw_db):
    assert block(client, viewer_headers, "203.0.113.9").status_code == 403
    assert client.delete(
        f"{API}/soar/blocked-ips/203.0.113.9", headers=viewer_headers
    ).status_code == 403
    assert raw_db.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0] == 0


def test_releasing_something_never_blocked_is_404_not_500(client, admin_headers):
    """The dict-based code raised KeyError on an absent address: an unhandled 500."""
    assert client.delete(
        f"{API}/soar/blocked-ips/203.0.113.200", headers=admin_headers
    ).status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# Destructive actions under enforced foreign keys
#
# PRAGMA foreign_keys is now ON for every SQLite connection (see config.py and
# database.py). These tests exist because that pragma changes what the delete
# endpoints are allowed to do: an ordering that "worked" with enforcement off
# raises IntegrityError with it on, and the only way to catch that is to run the
# real endpoints against a real file.
# ─────────────────────────────────────────────────────────────────────────────
async def test_foreign_key_enforcement_is_really_on(seed):
    """
    Everything below this line depends on the pragma actually being applied.

    SQLite ships with enforcement *off*, so the delete-ordering tests would still
    pass — against a database that never checks anything — if the connection listener
    were ever removed. Asserting the pragma here turns that regression into a failure
    instead of a silently vacuous test suite.
    """
    enabled = (await seed.execute(text("PRAGMA foreign_keys"))).scalar()
    assert enabled == 1, (
        "conftest must register the same per-connection pragmas production uses"
    )


async def test_a_block_rule_pointing_at_a_missing_threat_cannot_be_written(seed):
    """The reference the delete endpoints carefully release is a real constraint."""
    with pytest.raises(IntegrityError):
        seed.add(BlockedIP(
            ip_address="203.0.113.77", rule_id="ITAP-DANGLING",
            blocked_by="admin", blocked_at=datetime.utcnow(),
            status="active", threat_id="no-such-threat",
        ))
        await seed.commit()


async def seed_blocked_target(seed, *, ip: str = "203.0.113.40"):
    """A target with a threat, an incident on that threat, and a live block rule."""
    target = Target(domain="hostile.example", ip_address=ip, organization="ACME")
    seed.add(target)
    await seed.flush()

    threat = Threat(
        target_id=target.id, title="RDP brute force", severity=SeverityLevel.HIGH,
    )
    seed.add(threat)
    await seed.flush()

    seed.add(Incident(
        target_id=target.id, threat_id=threat.id, title="RDP brute force",
        severity=SeverityLevel.HIGH, status=IncidentStatus.OPEN,
    ))
    seed.add(BlockedIP(
        ip_address=ip, rule_id="ITAP-SEED0001", reason="seeded by test",
        blocked_by="admin", status="active", threat_id=threat.id,
    ))
    await seed.commit()
    return target


async def test_deleting_a_target_releases_block_rules_instead_of_deleting_them(
    client, admin_headers, raw_db, seed
):
    """
    A firewall rule must not silently disappear because someone tidied up a target.

    ``blocked_ips.threat_id`` is a real foreign key now, so the endpoint has to
    release the reference before the target's threats go away — otherwise the delete
    fails with an IntegrityError and the operator sees a 500 while the target stays.
    """
    target = await seed_blocked_target(seed)

    assert client.delete(
        f"{API}/targets/{target.id}", headers=admin_headers
    ).status_code == 200

    assert raw_db.execute("SELECT COUNT(*) FROM targets").fetchone()[0] == 0
    assert raw_db.execute("SELECT COUNT(*) FROM threats").fetchone()[0] == 0
    assert raw_db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0

    rule = raw_db.execute("SELECT threat_id, status FROM blocked_ips").fetchone()
    assert rule is not None, "the block outlives the target that justified it"
    assert rule["threat_id"] is None
    assert rule["status"] == "active"

    deleted = raw_db.execute(
        "SELECT actor, before_state FROM audit_logs WHERE action='target.delete'"
    ).fetchone()
    assert deleted["actor"] == "admin"
    assert "hostile.example" in deleted["before_state"]


async def test_wiping_history_keeps_the_firewall_running(
    client, admin_headers, raw_db, seed
):
    """
    "Wipe the demo data" is not a request to start accepting blocked traffic.

    It is also the endpoint most exposed to the delete-order bug: incidents reference
    threats, so incidents have to go first. With FK enforcement off that is invisible;
    with it on, the wrong order aborts the whole wipe.
    """
    await seed_blocked_target(seed, ip="203.0.113.41")

    response = client.delete(f"{API}/history/all", headers=admin_headers)
    assert response.status_code == 200

    for table in ("targets", "scans", "threats", "incidents"):
        assert raw_db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, table

    rule = raw_db.execute(
        "SELECT ip_address, threat_id, status FROM blocked_ips"
    ).fetchone()
    assert dict(rule) == {
        "ip_address": "203.0.113.41", "threat_id": None, "status": "active",
    }

    logged = raw_db.execute(
        "SELECT outcome, before_state FROM audit_logs WHERE action='history.delete_all'"
    ).fetchone()
    assert logged["outcome"] == "success"
    assert "targets" in logged["before_state"], (
        "the audit row must say what was destroyed, not just that something was"
    )


def test_archiving_the_session_is_audited(client, admin_headers, rows):
    assert client.post(
        f"{API}/system/new-session", headers=admin_headers
    ).status_code == 200
    assert rows("system.new_session")[0]["outcome"] == "success"


def test_a_refused_destructive_request_is_not_recorded_as_if_it_happened(
    client, viewer_headers, rows
):
    """
    A refusal is not an action, and the trail must not imply otherwise.

    ``require_roles`` raises before the handler runs, so a refusal cannot be recorded
    from inside the endpoint; refusals are visible in the structured request log
    instead. Pinning the boundary keeps the gap from being mistaken for an oversight —
    authentication is the one place where a *denied* attempt is written to the trail,
    because the attempt is only observable there.
    """
    assert client.delete(f"{API}/history/all", headers=viewer_headers).status_code == 403
    assert rows("history.delete_all") == []
