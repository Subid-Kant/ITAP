"""
ITAP — platform security controls (post-audit).

Each test here corresponds to a finding from the dev-phase audit and asserts the
*behaviour*, not the implementation: that the login endpoint throttles, that a
logged-out token stops working, that an unauthenticated WebSocket receives nothing,
that the CSP actually restricts scripts, and that a background monitor can be
stopped in milliseconds instead of waiting out its sleep.

These controls are easy to lose again during a refactor (reverting one decorator is
enough), so they are pinned.
"""
import asyncio
import json
import logging
import time
from unittest.mock import AsyncMock

import pytest
from starlette.websockets import WebSocketDisconnect

from app.core import security
from app.core.config import settings, Settings
from app.core.logging_filters import scrub, SecretRedactingFilter
from app.core.security import create_access_token, create_refresh_token
from app.services.monitoring import global_threat_feed as gtf_module
from app.services.monitoring import server_monitor as sm_module
from app.services.monitoring import machine_scanner as ms_module

API = "/api/v1"


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    """Login attempts are process-global state; every test starts and ends clean."""
    def _clear():
        with security._FAILED_LOGINS_LOCK:
            security._FAILED_LOGINS.clear()

    _clear()
    yield
    _clear()


# ─────────────────────────────────────────────────────────────────────────────
# C1 — a placeholder SECRET_KEY must not boot
# ─────────────────────────────────────────────────────────────────────────────
def test_placeholder_secret_key_is_refused():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        Settings(SECRET_KEY="CHANGE_ME_IN_PRODUCTION_USE_64_CHAR_RANDOM_STRING")


def test_short_secret_key_is_refused():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        Settings(SECRET_KEY="too-short")


def test_a_long_random_secret_key_is_accepted():
    assert Settings(SECRET_KEY="x" * 64).SECRET_KEY == "x" * 64


# ─────────────────────────────────────────────────────────────────────────────
# C2 — login throttling
# ─────────────────────────────────────────────────────────────────────────────
def test_login_is_throttled_after_repeated_failures(client):
    """RateLimitMiddleware exempts loopback, so this had to be its own control."""
    payload = {"username": "admin", "password": "definitely-not-the-password"}

    for attempt in range(security.LOGIN_MAX_ATTEMPTS):
        assert client.post(f"{API}/auth/login", json=payload).status_code == 401, attempt

    throttled = client.post(f"{API}/auth/login", json=payload)
    assert throttled.status_code == 429
    assert "Retry-After" in throttled.headers


def test_successful_login_clears_the_failure_counter(client):
    """One typo must not spend part of a real user's allowance."""
    bad = {"username": "admin", "password": "wrong"}
    for _ in range(security.LOGIN_MAX_ATTEMPTS - 1):
        client.post(f"{API}/auth/login", json=bad)

    good = {"username": "admin", "password": settings.ADMIN_PASSWORD}
    assert client.post(f"{API}/auth/login", json=good).status_code == 200

    # Counter is clear, so a full fresh run of failures is needed to trip the throttle.
    for attempt in range(security.LOGIN_MAX_ATTEMPTS):
        assert client.post(f"{API}/auth/login", json=bad).status_code == 401, attempt
    assert client.post(f"{API}/auth/login", json=bad).status_code == 429


def test_throttling_is_per_account_not_global(client):
    """A locked-out account must not lock out everyone else."""
    for _ in range(security.LOGIN_MAX_ATTEMPTS):
        client.post(f"{API}/auth/login", json={"username": "admin", "password": "wrong"})
    assert client.post(
        f"{API}/auth/login", json={"username": "admin", "password": "wrong"}
    ).status_code == 429

    ok = client.post(
        f"{API}/auth/login",
        json={"username": "analyst", "password": settings.ANALYST_PASSWORD},
    )
    assert ok.status_code == 200


def test_login_does_not_reveal_whether_a_username_exists(client):
    unknown = client.post(f"{API}/auth/login", json={"username": "ghost", "password": "x"})
    wrong_pw = client.post(f"{API}/auth/login", json={"username": "admin", "password": "x"})
    assert unknown.status_code == wrong_pw.status_code == 401
    assert unknown.json()["detail"] == wrong_pw.json()["detail"]


# ─────────────────────────────────────────────────────────────────────────────
# C3 — revocation and refresh rotation
# ─────────────────────────────────────────────────────────────────────────────
def test_access_tokens_carry_a_revocable_id():
    from app.core.security import decode_token
    payload = decode_token(create_access_token(data={"sub": "admin", "role": "admin"}))
    assert payload["jti"]
    assert payload["type"] == "access"


def test_logout_revokes_the_access_token(client):
    header_token = create_access_token(
        data={"sub": "admin", "role": "admin", "name": "ITAP Administrator"}
    )
    headers = {"Authorization": f"Bearer {header_token}"}

    assert client.get(f"{API}/auth/me", headers=headers).status_code == 200

    logged_out = client.post(f"{API}/auth/logout", headers=headers)
    assert logged_out.status_code == 200
    assert "access" in logged_out.json()["revoked"]

    after = client.get(f"{API}/auth/me", headers=headers)
    assert after.status_code == 401
    assert "revoked" in after.json()["detail"].lower()


def test_logout_also_revokes_the_refresh_token(client):
    login = client.post(
        f"{API}/auth/login",
        json={"username": "admin", "password": settings.ADMIN_PASSWORD},
    ).json()
    headers = {"Authorization": f"Bearer {login['access_token']}"}

    assert client.post(
        f"{API}/auth/logout", json={"refresh_token": login["refresh_token"]}, headers=headers
    ).status_code == 200

    replay = client.post(f"{API}/auth/refresh", json={"token": login["refresh_token"]})
    assert replay.status_code == 401


def test_refresh_token_is_rotated_and_cannot_be_replayed(client):
    login = client.post(
        f"{API}/auth/login",
        json={"username": "admin", "password": settings.ADMIN_PASSWORD},
    ).json()

    first = client.post(f"{API}/auth/refresh", json={"token": login["refresh_token"]})
    assert first.status_code == 200
    body = first.json()
    assert body["refresh_token"] != login["refresh_token"], "the token must rotate"

    replay = client.post(f"{API}/auth/refresh", json={"token": login["refresh_token"]})
    assert replay.status_code == 401, "a spent refresh token must not be reusable"

    # The rotated token still works, so rotation did not simply break refresh.
    second = client.post(f"{API}/auth/refresh", json={"token": body["refresh_token"]})
    assert second.status_code == 200


def test_a_token_without_a_jti_is_refused(client):
    """Tokens minted before revocation existed could never be revoked, so they die."""
    from jose import jwt
    legacy = jwt.encode(
        {"sub": "admin", "role": "admin", "type": "access"},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    resp = client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {legacy}"})
    assert resp.status_code == 401


def test_a_refresh_token_cannot_be_used_as_an_access_token(client):
    refresh = create_refresh_token(data={"sub": "admin", "role": "admin"})
    resp = client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {refresh}"})
    assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# C7 — WebSocket authentication
# ─────────────────────────────────────────────────────────────────────────────
def test_websocket_rejects_a_bad_token(client):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/live") as ws:
            ws.send_text(json.dumps({"type": "auth", "token": "not-a-jwt"}))
            ws.receive_text()
    assert exc.value.code == 4401


def test_websocket_rejects_a_revoked_token(client):
    token = create_access_token(data={"sub": "admin", "role": "admin"})
    client.post(f"{API}/auth/logout", headers={"Authorization": f"Bearer {token}"})

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/live") as ws:
            ws.send_text(json.dumps({"type": "auth", "token": token}))
            ws.receive_text()
    assert exc.value.code == 4401


def test_websocket_rejects_a_non_handshake_first_frame(client):
    token = create_access_token(data={"sub": "admin", "role": "admin"})
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/live") as ws:
            ws.send_text("ping")   # not an auth frame
            ws.receive_text()
    assert exc.value.code == 4401


def test_websocket_accepts_a_valid_access_token(client):
    token = create_access_token(data={"sub": "admin", "role": "admin"})
    with client.websocket_connect("/ws/live") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token}))
        message = ws.receive_json()
        assert message["type"] == "connected"
        assert message["user"] == "admin"
        # Now an ordinary authenticated socket: heartbeat still works.
        ws.send_text("ping")
        assert ws.receive_text() == "pong"


# ─────────────────────────────────────────────────────────────────────────────
# C10 — security headers
# ─────────────────────────────────────────────────────────────────────────────
def test_csp_forbids_inline_and_eval_scripts(client):
    csp = client.get("/health").headers["Content-Security-Policy"]
    script_src = csp.split("script-src")[1].split(";")[0]

    assert "'self'" in script_src
    assert "unsafe-inline" not in script_src
    assert "unsafe-eval" not in script_src


def test_csp_restricts_objects_frames_and_base_uri(client):
    csp = client.get("/health").headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "form-action 'self'" in csp


def test_csp_connect_src_covers_the_api_and_its_websocket(client):
    csp = client.get("/health").headers["Content-Security-Policy"]
    connect_src = csp.split("connect-src")[1].split(";")[0]
    assert "'self'" in connect_src
    assert f"ws://localhost:{settings.PORT}" in connect_src


def test_response_does_not_advertise_the_stack(client):
    headers = client.get("/health").headers
    assert "X-Powered-By" not in headers
    assert "X-XSS-Protection" not in headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"


# ─────────────────────────────────────────────────────────────────────────────
# C4 / C6 — outbound TLS and credential handling
# ─────────────────────────────────────────────────────────────────────────────
def test_threat_feed_sources_do_not_disable_tls_verification():
    """ssl=False let anyone on the path rewrite the feed into CRITICAL incidents."""
    import inspect
    import re
    # Compare against code only: the explanation comment above those calls quotes
    # "ssl=False" to record why it is not used.
    source = inspect.getsource(gtf_module)
    code = "\n".join(line.split("#")[0] for line in source.splitlines())
    assert not re.search(r"ssl\s*=\s*False", code)
    assert "session.get(" in code   # the calls are still there, just verified


def test_shodan_key_is_not_interpolated_into_the_url():
    import inspect
    from app.services.osint import osint_service as osint_module
    source = inspect.getsource(osint_module)
    assert "?key={settings.SHODAN_API_KEY}" not in source
    assert 'params={"key": settings.SHODAN_API_KEY}' in source


def test_log_scrubber_redacts_credentials():
    assert "abc123SECRET" not in scrub("https://api.shodan.io/host/1.2.3.4?key=abc123SECRET")
    assert "[REDACTED]" in scrub("key=abc123SECRET")
    assert "[REDACTED]" in scrub("SHODAN_API_KEY='super-secret-value-1234'")
    assert "[REDACTED]" in scrub("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payloadpart.sigpart")
    assert "supersecretjwtvalue123" not in scrub("token=supersecretjwtvalue123")


def test_log_scrubber_keeps_the_parameter_name():
    assert scrub("apikey=abcdef12345678") == "apikey=[REDACTED]"


def test_log_scrubber_leaves_ordinary_text_alone():
    text = "Scan complete for example.com: 3 threats"
    assert scrub(text) == text


def test_scrubbing_filter_rewrites_records():
    record = logging.LogRecord(
        "itap.test", logging.WARNING, __file__, 1,
        "call failed: %s", ("https://api.shodan.io/host/1.2.3.4?key=abcdef123456",), None,
    )
    assert SecretRedactingFilter().filter(record) is True
    assert "abcdef123456" not in record.getMessage()
    assert "[REDACTED]" in record.getMessage()


# ─────────────────────────────────────────────────────────────────────────────
# A7 — background monitors must actually stop
# ─────────────────────────────────────────────────────────────────────────────
async def _assert_stops_promptly(service, interval_seconds: int):
    """Start `service` and prove stop() returns without waiting out its sleep.

    The bug being pinned: ``stop()`` only flipped ``is_running`` while the loop sat
    in ``asyncio.sleep(<interval>)``, so shutdown blocked for up to an hour (the
    global threat feed's interval) and graceful-shutdown logging never ran.
    """
    await service.start()
    try:
        await asyncio.sleep(0.05)   # let the loop reach its wait
        started = time.perf_counter()
        await service.stop()
        elapsed = time.perf_counter() - started
    finally:
        if getattr(service, "is_running", False):
            await service.stop()

    assert service.is_running is False
    assert elapsed < 2.0, (
        f"stop() took {elapsed:.2f}s against a {interval_seconds}s interval — it is "
        "waiting out the sleep instead of waking on cancellation"
    )
    assert service._task is None


async def test_server_monitor_stops_promptly(monkeypatch):
    monkeypatch.setattr(
        sm_module.server_monitor, "get_current_stats",
        AsyncMock(return_value={
            "cpu_percent": 1, "memory_percent": 1, "memory_used_gb": 1.0,
            "memory_total_gb": 8.0, "disk_percent": 1, "active_connections": 0,
            "connections_sample": [], "hostname": "test", "timestamp": "t",
        }),
    )
    monkeypatch.setattr(sm_module.server_monitor, "_evaluate_thresholds", AsyncMock())
    await _assert_stops_promptly(sm_module.server_monitor, interval_seconds=15)


async def test_global_threat_feed_stops_promptly(monkeypatch):
    monkeypatch.setattr(gtf_module.global_threat_feed, "_process_feeds", AsyncMock())
    await _assert_stops_promptly(gtf_module.global_threat_feed, interval_seconds=3600)


async def test_machine_scanner_stops_promptly(monkeypatch):
    monkeypatch.setattr(ms_module.settings, "MACHINE_SCAN_ENABLED", True)
    monkeypatch.setattr(
        ms_module.machine_scanner, "_run_scan",
        AsyncMock(return_value={
            "host": {"city": "x", "country": "y"}, "connections": [], "threat_count": 0,
        }),
    )
    await _assert_stops_promptly(ms_module.machine_scanner, interval_seconds=60)


async def test_machine_scanner_is_opt_in(monkeypatch):
    """It ships this host's network inventory to a third party, so it is off by default."""
    monkeypatch.setattr(ms_module.settings, "MACHINE_SCAN_ENABLED", False)
    await ms_module.machine_scanner.start()
    try:
        assert ms_module.machine_scanner.is_running is False
        assert ms_module.machine_scanner._task is None
        result = await ms_module.machine_scanner.get_result()
        assert result["enabled"] is False
    finally:
        await ms_module.machine_scanner.stop()


# ─────────────────────────────────────────────────────────────────────────────
# C9 — internal addresses never reach the geolocation provider
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.5",          # RFC1918
        "172.16.4.1",        # RFC1918
        "192.168.1.10",      # RFC1918
        "127.0.0.1",         # loopback
        "169.254.10.10",     # link-local
        "100.64.0.1",        # CGNAT — missed by the old prefix list
        "0.0.0.0",           # unspecified
        "224.0.0.1",         # multicast
        "::1",               # IPv6 loopback
        "fe80::1",           # IPv6 link-local
        "fd00::1",           # IPv6 unique-local
        "not-an-address",    # unparseable must fail closed
    ],
)
def test_internal_addresses_are_redacted_for_the_geolocation_provider(address):
    assert ms_module._is_private(address) is True


@pytest.mark.parametrize(
    "address", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"]
)
def test_public_addresses_are_still_geolocated(address):
    assert ms_module._is_private(address) is False


def test_geolocation_base_url_is_configurable():
    """The free ip-api tier is HTTP-only, so the endpoint is a deployment decision."""
    base = ms_module.machine_scanner.ip_api_base_url
    assert base == settings.GEOLOCATION_API_BASE.rstrip("/")
    assert ms_module.machine_scanner.ip_api_batch_url == f"{base}/batch"


# ─────────────────────────────────────────────────────────────────────────────
# A2 — SPA serving and path containment
# ─────────────────────────────────────────────────────────────────────────────
def test_spa_build_path_is_resolved_relative_to_the_repo():
    """One extra dirname() here silently disabled the whole SPA branch."""
    import os
    import main
    expected = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(main.__file__))), "frontend", "dist"
    )
    assert os.path.realpath(main.FRONTEND_BUILD) == os.path.realpath(expected)
    assert os.path.isdir(main.FRONTEND_BUILD)   # the shipped build is found


def test_spa_serves_a_real_asset(client):
    resp = client.get("/favicon.svg")
    assert resp.status_code == 200
    assert "svg" in resp.headers["content-type"]


def test_unknown_client_route_falls_back_to_index_html(client):
    resp = client.get("/some/deep/dashboard/route")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_spa_route_cannot_read_files_outside_the_build(client):
    """The traversal primitive: percent-encoded dot-segments defeat normalisation.

    httpx does not collapse ``%2e%2e``, so the server receives the encoded path and
    Starlette decodes it into ``../../<something>``. A canary file with a unique
    marker proves the containment check is what stopped it (rather than the request
    being normalised away, or a would-be-secret happening not to be in the body).
    """
    import pathlib

    canary = pathlib.Path(__file__).resolve().parent / "pytest.ini"
    canary_marker = "[pytest]"          # exists only in that file
    assert canary_marker in canary.read_text(encoding="utf-8")

    for attempt in (
        "/%2e%2e/%2e%2e/backend/pytest.ini",     # canary, outside the build
        "/%2e%2e%2f%2e%2e%2fbackend%2f.env",     # live API keys
        "/%2e%2e/%2e%2e/%2e%2e/backend/.env",
        "/%2e%2e/%2e%2e/backend/main.py",
    ):
        resp = client.get(attempt)
        assert resp.status_code == 200, attempt
        body = resp.text
        assert canary_marker not in body, f"{attempt} escaped the web root"
        assert "SECRET_KEY" not in body, f"{attempt} disclosed .env"
        assert "SHODAN_API_KEY" not in body, f"{attempt} disclosed .env"
        # Containment failed -> the SPA fallback, not a file from outside dist/.
        assert "text/html" in resp.headers["content-type"], attempt


def test_unknown_api_route_is_a_404_not_spa_html(client):
    """Otherwise a typo'd endpoint answers 200 with a page and looks fine."""
    resp = client.get(f"{API}/definitely-not-a-route")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Not found"
