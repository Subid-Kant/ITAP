"""
ITAP v2.0 — API integration tests.

The suite is hermetic by construction (see conftest.py): a throwaway SQLite file
per test, telemetry redirected into tmp_path, the LLM/OSINT/Nmap boundaries
stubbed, and any outbound aiohttp call turned into a failure.

Previously this module pointed an async engine at ``sqlite+aiosqlite:///:memory:``
(so every request saw an empty, table-less database), declared a
``test_scan_authorization_nmap_blocking`` whose only assertion was ``pass``, and
accepted any of ``[200, 401]`` from the rate-limiter check — meaning a green run
proved very little. Everything below asserts a specific outcome.
"""
import json
import uuid
from unittest.mock import Mock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.middleware import RateLimitMiddleware
from app.services.telemetry_service import TelemetryCollector


# ─────────────────────────────────────────────────────────────────────────────
# Authentication
# ─────────────────────────────────────────────────────────────────────────────
def test_unauthenticated_request_is_rejected(client):
    assert client.get("/api/v1/targets").status_code == 401


def test_forged_token_is_rejected(client):
    resp = client.get(
        "/api/v1/targets", headers={"Authorization": "Bearer not-a-real-token"}
    )
    assert resp.status_code == 401


def test_login_returns_usable_tokens(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": settings.ADMIN_PASSWORD},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["role"] == "admin"

    me = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert me.status_code == 200
    assert me.json()["username"] == "admin"


def test_login_rejects_wrong_password(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "definitely-not-the-password"},
    )
    assert resp.status_code == 401


def test_refresh_token_cannot_be_used_as_access_token(client):
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": settings.ADMIN_PASSWORD},
    ).json()
    resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {login['refresh_token']}"},
    )
    assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# Authorization (roles)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "role_fixture", ["admin_headers", "analyst_headers", "viewer_headers"]
)
def test_any_authenticated_role_can_read_targets(client, request, role_fixture):
    headers = request.getfixturevalue(role_fixture)
    assert client.get("/api/v1/targets", headers=headers).status_code == 200


def test_viewer_cannot_delete_target_but_analyst_can(
    client, admin_headers, analyst_headers, viewer_headers
):
    target_id = client.post(
        "/api/v1/targets",
        headers=admin_headers,
        json={"domain": f"del-{uuid.uuid4().hex[:8]}.example.com"},
    ).json()["id"]

    blocked = client.delete(f"/api/v1/targets/{target_id}", headers=viewer_headers)
    assert blocked.status_code == 403

    allowed = client.delete(f"/api/v1/targets/{target_id}", headers=analyst_headers)
    assert allowed.status_code == 200
    assert allowed.json()["target_id"] == target_id


# ─────────────────────────────────────────────────────────────────────────────
# Scan lifecycle
# ─────────────────────────────────────────────────────────────────────────────
def _create_target(client, headers, domain=None, ip_address=None):
    payload = {"domain": domain or f"host-{uuid.uuid4().hex[:8]}.example.com"}
    if ip_address:
        payload["ip_address"] = ip_address
    resp = client.post("/api/v1/targets", headers=headers, json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()["id"], payload["domain"]


def test_scan_requires_authentication(client, admin_headers, osint_scan_mock):
    target_id, _ = _create_target(client, admin_headers)
    assert (
        client.post("/api/v1/scan", json={"target_id": target_id}).status_code == 401
    )


def test_scan_lifecycle(client, admin_headers, osint_scan_mock):
    """
    Target -> OSINT scan -> persisted scan/threats -> re-scan -> telemetry.

    Asserts on the content of the response, not just the status code: the
    critical CVE in the stubbed OSINT payload must become a Threat, and only the
    above-threshold LLM prediction may be promoted into a predicted threat.
    """
    target_id, domain = _create_target(client, admin_headers)

    resp = client.post(
        "/api/v1/scan", headers=admin_headers, json={"target_id": target_id}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["target"] == domain
    assert body["risk_score"] == 72.5
    assert body["risk_level"] == "HIGH"
    assert body["summary"]["open_ports"] == [80, 443]

    # Critical OSINT CVE -> Threat
    assert "CVE Found: CVE-2021-44228 on nginx" in body["threats_created"]
    # Above-threshold prediction -> Threat; the 0.41 one must NOT be promoted.
    assert "Predicted: Remote Code Execution" in body["threats_created"]
    assert "Predicted: Information Disclosure" not in body["threats_created"]

    # The scan row was written and is readable back
    scan_id = body["scan_id"]
    stored = client.get(f"/api/v1/scan/{scan_id}", headers=admin_headers)
    assert stored.status_code == 200, stored.text
    assert stored.json()["scan_type"] == "full_osint"

    # Re-scanning reuses the existing row instead of raising MultipleResultsFound
    # (the historical scalar_one_or_none 500 on a second scan of one target).
    second = client.post(
        "/api/v1/scan", headers=admin_headers, json={"target_id": target_id}
    )
    assert second.status_code == 200, second.text
    assert second.json()["scan_id"] == scan_id

    # Telemetry ran for the scan and landed in the isolated tmp dataset
    with open(TelemetryCollector.DATASET_PATH, "r", encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    assert any(r["domain"] == domain and r["training_eligible"] for r in records)


def test_unknown_target_scan_returns_404(client, admin_headers, osint_scan_mock):
    resp = client.post(
        "/api/v1/scan", headers=admin_headers, json={"target_id": "does-not-exist"}
    )
    assert resp.status_code == 404


def test_viewer_cannot_start_nmap_scan(client, admin_headers, viewer_headers,
                                       osint_scan_mock):
    """
    Replaces the old no-op test that ended in ``pass`` and asserted nothing.
    """
    target_id, _ = _create_target(client, admin_headers)
    resp = client.post(
        "/api/v1/scan",
        headers=viewer_headers,
        json={"target_id": target_id, "nmap_enabled": True},
    )
    assert resp.status_code == 403
    osint_scan_mock.assert_not_called()


def test_internal_ip_nmap_scan_is_blocked(client, admin_headers, osint_scan_mock):
    """SSRF guard: an address that resolves to loopback must be refused."""
    target_id, _ = _create_target(client, admin_headers, domain="127.0.0.1")
    with patch("socket.gethostbyname", return_value="127.0.0.1"):
        resp = client.post(
            "/api/v1/scan",
            headers=admin_headers,
            json={"target_id": target_id, "nmap_enabled": True},
        )
    assert resp.status_code == 400
    assert "internal" in resp.json()["detail"].lower()
    osint_scan_mock.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Nmap input validation (command-injection defence)
#
# ``target``/``ports``/``scan_type`` are interpolated straight into the Nmap CLI
# argument string, so every one of them is a command-injection primitive unless
# the route refuses it first.
# ─────────────────────────────────────────────────────────────────────────────
PUBLIC_IP = "203.0.113.9"  # RFC 5737 documentation range — never routable


@pytest.fixture
def nmap_worker():
    """Stub the thread worker so no real Nmap binary is ever executed."""
    with patch(
        "app.services.osint.nmap_service.NmapService._run_scan_sync",
        new=Mock(
            return_value={
                "status": "completed",
                "open_ports": [22, 80],
                "services": [],
                "vulnerabilities": [],
                "duration_seconds": 1.0,
            }
        ),
    ) as worker:
        yield worker


def test_standalone_nmap_accepts_a_valid_spec(client, admin_headers, nmap_worker):
    target_id, _ = _create_target(client, admin_headers, ip_address=PUBLIC_IP)
    resp = client.post(
        "/api/v1/scan/nmap",
        headers=admin_headers,
        params={"target_id": target_id, "scan_type": "quick", "ports": "22,80,443"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["open_ports"] == [22, 80]
    nmap_worker.assert_called_once()


@pytest.mark.parametrize(
    "params,expected_fragment",
    [
        ({"ports": "80; shutdown -h now"}, "invalid ports"),
        ({"ports": "443|curl evil.example.com"}, "invalid ports"),
        ({"ports": "80&&whoami"}, "invalid ports"),
        ({"ports": "70000"}, "out of range"),
        ({"scan_type": "standard; --script=vuln"}, "invalid scan_type"),
        ({"scan_type": "aggressive"}, "invalid scan_type"),
    ],
)
def test_standalone_nmap_rejects_injection(client, admin_headers, nmap_worker,
                                           params, expected_fragment):
    target_id, _ = _create_target(client, admin_headers, ip_address=PUBLIC_IP)
    query = {"target_id": target_id}
    query.update(params)
    resp = client.post("/api/v1/scan/nmap", headers=admin_headers, params=query)
    assert resp.status_code == 400, resp.text
    assert expected_fragment in resp.json()["detail"].lower()
    # The whole point: the argument never reaches the Nmap worker.
    nmap_worker.assert_not_called()


def test_standalone_nmap_requires_admin(client, admin_headers, viewer_headers, nmap_worker):
    target_id, _ = _create_target(client, admin_headers, ip_address=PUBLIC_IP)
    resp = client.post(
        "/api/v1/scan/nmap",
        headers=viewer_headers,
        params={"target_id": target_id, "scan_type": "quick"},
    )
    assert resp.status_code == 403
    nmap_worker.assert_not_called()


def test_hybrid_scan_rejects_hostile_ports_at_the_schema(client, admin_headers,
                                                        osint_scan_mock):
    """``ScanRequest`` refuses the payload before the route body runs (422)."""
    target_id, _ = _create_target(client, admin_headers)
    resp = client.post(
        "/api/v1/scan",
        headers=admin_headers,
        json={
            "target_id": target_id,
            "nmap_enabled": True,
            "nmap_custom_ports": "80; cat /etc/passwd",
        },
    )
    assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiter
#
# The old version of this test accepted 200 *or* 401 from an unauthenticated
# request, so it passed whether the limiter worked, was missing, or crashed the
# app on the first dictionary access. It now drives the middleware directly.
# ─────────────────────────────────────────────────────────────────────────────
def test_rate_limiter_returns_429_once_the_window_is_full():
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, max_requests=3, window_seconds=60)

    @app.get("/probe")
    async def probe():
        return {"ok": True}

    # A non-loopback X-Forwarded-For keeps the limiter from taking its
    # localhost bypass, and keeps this test's bucket separate from other tests.
    limiter_client = TestClient(app, headers={"X-Forwarded-For": "203.0.113.77"})
    codes = [limiter_client.get("/probe").status_code for _ in range(5)]

    assert codes[:3] == [200, 200, 200], codes
    assert codes[3:] == [429, 429], codes
    assert "Retry-After" in limiter_client.get("/probe").headers
