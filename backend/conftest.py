"""
ITAP v2.0 — shared pytest fixtures.

This file did not use to exist, which meant every test module had to wire up its
own database, auth tokens and mocks — and most of them got it wrong in a way that
made the suite look healthier than the product:

* ``test_integration.py`` pointed an async engine at ``sqlite+aiosqlite:///:memory:``.
  Every new connection to that URL is a *brand new empty database*, so the tables
  created in the setup fixture were invisible to the requests and every DB-backed
  assertion was vacuous.
* ``TelemetryCollector`` wrote straight into ``data/telemetry_dataset.jsonl``, so
  running the tests polluted the real ML training corpus.
* Nothing stubbed ``LocalLLMService`` or the OSINT providers, so ``POST /scan``
  tried to reach Ollama, Shodan and NVD over the network and passed anyway
  whenever those calls failed soft.

Everything that has to be true for a test run to be meaningful lives here.
"""
import copy
import os
import sqlite3
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest
import sqlalchemy
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# ─────────────────────────────────────────────────────────────────────────────
# Test-time configuration — MUST happen before any ``app.*`` import.
#
# ``app.core.config.settings`` is instantiated at import time, so an override
# applied after ``import main`` would be silently ignored. DATABASE_URL is
# redirected to a throwaway file so a stray ``init_db()`` or
# ``async_session_factory`` call can never mutate the developer's real
# ``backend/itap.db``.
# ─────────────────────────────────────────────────────────────────────────────
TEST_ARTIFACT_DIR = BACKEND_DIR / ".pytest_tmp"
TEST_ARTIFACT_DIR.mkdir(exist_ok=True)

os.environ.setdefault("SECRET_KEY", "itap-test-secret-key-do-not-use-in-production")
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = (
    f"sqlite+aiosqlite:///{(TEST_ARTIFACT_DIR / 'pytest_default.db').as_posix()}"
)

from app.core.security import create_access_token  # noqa: E402
from app.db.database import Base, get_db  # noqa: E402

# Only exists when the configured URL is SQLite, which is what the test suite uses.
try:
    from app.db.database import _apply_sqlite_pragmas  # noqa: E402
except ImportError:      # pragma: no cover - only when pointed at PostgreSQL
    _apply_sqlite_pragmas = None

from app.services.ml.llm_service import LocalLLMService  # noqa: E402
from app.services.telemetry_service import TelemetryCollector  # noqa: E402
from main import app  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# Offline guarantees
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def block_outbound_network(request):
    """
    Fail loudly instead of making a real outbound HTTP call.

    Every OSINT provider, the NVD feed and the Ollama client go through
    ``aiohttp.ClientSession``, so blocking ``_request`` covers Shodan, VirusTotal,
    OTX, Censys, NVD, Slack/Teams webhooks and LLM inference in one place. Tests
    that genuinely need the network must opt in with ``@pytest.mark.live``.
    """
    if request.node.get_closest_marker("live"):
        yield
        return

    async def _blocked(self, *args, **kwargs):
        target = args[1] if len(args) > 1 else kwargs.get("url")
        raise AssertionError(
            f"Blocked outbound aiohttp call to {target!r}. The backend suite must "
            "run offline: patch the owning service (OSINTAggregator / "
            "LocalLLMService / NmapService) or mark the test @pytest.mark.live."
        )

    with patch.object(aiohttp.ClientSession, "_request", _blocked):
        yield


@pytest.fixture(autouse=True)
def isolate_telemetry(tmp_path, monkeypatch):
    """
    Redirect the telemetry collector into the test's tmp dir.

    Without this, every ``POST /scan`` appended rows to the real
    ``data/telemetry_dataset.jsonl`` and rewrote ``telemetry_history.json``,
    corrupting the ML training corpus and making the concurrency test depend on
    whatever a previous developer had run.
    """
    monkeypatch.setattr(
        TelemetryCollector, "DATASET_PATH", str(tmp_path / "telemetry_dataset.jsonl")
    )
    monkeypatch.setattr(
        TelemetryCollector, "HISTORY_PATH", str(tmp_path / "telemetry_history.json")
    )
    # No lock reset: the collector's write lock is a process-wide threading.RLock,
    # so it is loop-agnostic and carries over between tests untouched.
    yield


# ─────────────────────────────────────────────────────────────────────────────
# Deterministic LLM stubs
# ─────────────────────────────────────────────────────────────────────────────
STUB_PREDICTIONS = [
    {
        "predicted_cve": "CVE-2021-44228",
        "predicted_attack_type": "Remote Code Execution",
        "probability": 0.87,
        "confidence": "high",
        "cvss_score": 9.8,
        "time_window_hours": 72,
        "attack_vector": "NETWORK",
        "root_cause": "Untrusted JNDI lookup in the logging component.",
        "cve_description": "JNDI injection allowing remote code execution.",
        "affected_components": "logging 2.14.0",
        "attack_vector_detail": "Remote, no authentication required.",
        "remediation": ["Upgrade the logging library", "Block outbound JNDI/LDAP"],
    },
    {
        "predicted_cve": "CVE-2014-0160",
        "predicted_attack_type": "Information Disclosure",
        "probability": 0.41,
        "confidence": "medium",
        "cvss_score": 7.5,
        "time_window_hours": 72,
        "attack_vector": "NETWORK",
        "root_cause": "Out-of-bounds read in TLS heartbeat handling.",
        "cve_description": "Memory disclosure via malformed heartbeat.",
        "affected_components": "openssl 1.0.1",
        "attack_vector_detail": "Remote, no authentication required.",
        "remediation": ["Upgrade OpenSSL"],
    },
]


@pytest.fixture(autouse=True)
def mock_local_llm():
    """
    Replace Ollama with deterministic stubs.

    ``generate_prediction`` used to reach a local Ollama daemon and silently fall
    back to a heuristic when the daemon was absent, which meant the
    threat-creation branch of ``POST /scan`` was only covered by accident. Two
    fixed predictions come back — one above and one below the 0.5 promotion
    threshold — so both branches run on every execution.
    """
    with patch.object(
        LocalLLMService, "is_ollama_available", new=AsyncMock(return_value=False)
    ), patch.object(
        LocalLLMService,
        "generate_prediction",
        new=AsyncMock(return_value=copy.deepcopy(STUB_PREDICTIONS)),
    ), patch.object(
        LocalLLMService,
        "generate_remediation_for_active_threat",
        new=AsyncMock(
            return_value={
                "root_cause": "Stale service banner exposed to the internet.",
                "attack_vector_detail": "Remote, unauthenticated.",
                "remediation": ["Upgrade the service", "Restrict exposure"],
            }
        ),
    ):
        yield


# ─────────────────────────────────────────────────────────────────────────────
# Database + client
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def test_db_path(tmp_path):
    """
    A throwaway SQLite file that already holds the full schema.

    The schema is built with a *synchronous* engine on purpose: the async engine
    that serves requests lives inside TestClient's portal loop, and creating the
    tables from there would hand a connection owned by that loop back to pytest's
    loop. A file (rather than ``:memory:``) is used because every new connection
    to an in-memory URL is a separate, empty database.
    """
    path = tmp_path / "itap_test.db"
    sync_engine = sqlalchemy.create_engine(f"sqlite:///{path.as_posix()}")
    Base.metadata.create_all(sync_engine)
    sync_engine.dispose()
    return path


@pytest.fixture
def make_client():
    """
    Build a ``TestClient`` bound to a given SQLite file, and clean it up after.

    Exposed as a factory because some tests need to prove a state change outlives the
    process that made it — for those, one client performs the action and a second
    client (a fresh engine, same file) reads it back.
    """
    opened = []

    def _make(db_path) -> TestClient:
        engine = create_async_engine(
            f"sqlite+aiosqlite:///{Path(db_path).as_posix()}",
            echo=False,
            poolclass=NullPool,
        )
        # Same per-connection pragmas production installs (WAL, busy_timeout,
        # foreign_keys=ON). Without this the test database silently skips foreign
        # key enforcement, so referential bugs in the delete paths — the exact
        # thing those pragmas exist to catch — would only appear after deploy.
        if _apply_sqlite_pragmas is not None:
            event.listen(engine.sync_engine, "connect", _apply_sqlite_pragmas)
        SessionLocal = async_sessionmaker(
            bind=engine, expire_on_commit=False, autoflush=False
        )

        async def override_get_db():
            async with SessionLocal() as session:
                yield session

        app.dependency_overrides[get_db] = override_get_db
        opened.append(engine)
        return TestClient(app)

    yield _make

    for engine in opened:
        # dispose(), not close(): AsyncEngine.sync_engine is a sync Engine, which
        # has no close(). NullPool keeps nothing parked, so this cannot block on a
        # connection owned by the portal loop that is already shut down.
        engine.sync_engine.dispose()
    # Clearing matters: an override left behind leaks into every later test
    # module, including ones that expect the production wiring.
    app.dependency_overrides.clear()


@pytest.fixture
def client(test_db_path, make_client):
    """
    TestClient wired to an isolated per-test database.

    ``NullPool`` is deliberate: each request opens and closes its own aiosqlite
    connection, so no connection is ever passed from the pytest event loop to
    TestClient's portal loop (the thing that makes async SQLite hang outright).
    The lifespan context is not entered, so background monitors never start and
    the real ``backend/itap.db`` is neither opened nor written.
    """
    return make_client(test_db_path)


@pytest.fixture
def raw_db(test_db_path):
    """
    A plain ``sqlite3`` connection to the per-test database, for reading rows back.

    Some assertions are about the *storage* rather than the API — that an audit row
    really landed, that a block rule was kept as history instead of deleted, that no
    row dangles. Reading the file with the stdlib driver keeps those assertions
    independent of the ORM the endpoints use.
    """
    conn = sqlite3.connect(str(test_db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────────────────────
def _token(username: str, role: str) -> str:
    return create_access_token(data={"sub": username, "role": role})


@pytest.fixture
def admin_token() -> str:
    return _token("admin", "admin")


@pytest.fixture
def analyst_token() -> str:
    return _token("analyst", "analyst")


@pytest.fixture
def viewer_token() -> str:
    return _token("viewer", "viewer")


@pytest.fixture
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def analyst_headers(analyst_token):
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


# ─────────────────────────────────────────────────────────────────────────────
# OSINT stub
# ─────────────────────────────────────────────────────────────────────────────
SAMPLE_OSINT_RESULT = {
    "summary": {
        "open_ports": [80, 443],
        "known_vulns": 2,
        "vt_malicious": 0,
        "recent_cves": 2,
        "otx_pulses": 4,
        "geolocation": {"country": "US", "lat": 37.7, "lon": -122.4},
    },
    "risk_score": 72.5,
    "risk_level": "HIGH",
    "vulnerabilities_by_service": [
        {
            "service": "nginx",
            "port": 443,
            "version": "1.18.0",
            "cves": [
                {
                    "cve_id": "CVE-2021-44228",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "description": "JNDI injection leading to remote code execution.",
                }
            ],
        }
    ],
    "sources": {
        "shodan": {"ports": [80, 443], "vulns": ["CVE-2021-44228"]},
        "cve_nvd": [
            {
                "cve_id": "CVE-2021-44228",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "description": "JNDI injection leading to remote code execution.",
            }
        ],
    },
    "threat_surface": [],
    "osint_fingerprint": {},
}


@pytest.fixture
def osint_scan_mock():
    """
    Stub ``POST /scan``'s aggregator call and hand back the mock.

    The critical CVE in the payload is deliberate: it drives the
    ``cvss_score >= 7.0`` branch that creates a Threat row, so the test proves the
    scan actually persisted findings instead of only returning 200.
    """
    with patch(
        "app.api.routes.api.OSINTAggregator.full_scan", new_callable=AsyncMock
    ) as mocked:
        mocked.return_value = copy.deepcopy(SAMPLE_OSINT_RESULT)
        yield mocked
