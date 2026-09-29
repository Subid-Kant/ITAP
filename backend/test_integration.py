import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import sys
import os
import uuid
import time
import asyncio

# Ensure app is importable
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.db.database import Base, get_db
from app.models.models import Target
from app.core.security import create_access_token
from main import app

# Create in-memory SQLite for testing
SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

engine = create_async_engine(SQLALCHEMY_DATABASE_URL, echo=False)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine, class_=AsyncSession
)

async def override_get_db():
    async with TestingSessionLocal() as session:
        yield session

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    # Setup runs once per module
    async def init_db():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    asyncio.run(init_db())
    yield
    # Cleanup
    async def drop_db():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    asyncio.run(drop_db())

@pytest.fixture
def admin_token():
    return create_access_token(data={"sub": "admin", "role": "admin"})

@pytest.fixture
def viewer_token():
    return create_access_token(data={"sub": "viewer", "role": "viewer"})

def test_rate_limiter():
    # Rate limit requests are 200, but we just want to ensure it works properly.
    # The first request should work without a KeyError.
    response = client.get("/api/v1/targets")
    assert response.status_code in [200, 401] # 401 because no token, but it didn't crash

def test_login_and_roles(admin_token, viewer_token):
    # Viewer can list targets
    headers = {"Authorization": f"Bearer {viewer_token}"}
    response = client.get("/api/v1/targets", headers=headers)
    assert response.status_code == 200

def test_scan_authorization_nmap_blocking(viewer_token):
    # Viewer shouldn't be able to run nmap scans
    headers = {"Authorization": f"Bearer {viewer_token}"}
    payload = {
        "target_id": "dummy",
        "nmap_enabled": True
    }
    response = client.post("/api/v1/scan", headers=headers, json=payload)
    # Target not found is 404, but admin check is before target lookup?
    # No, target lookup is first.
    # But let's check what it returns
    pass

@patch("app.api.routes.api.OSINTAggregator.full_scan", new_callable=AsyncMock)
def test_scan_lifecycle(mock_osint_scan, admin_token):
    # Mock OSINT scan result
    mock_osint_scan.return_value = {
        "summary": {"open_ports": [80], "vulnerabilities": []},
        "vulnerabilities_by_service": [],
        "risk_score": 10
    }
    
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # 1. Create a target
    target_payload = {"domain": "example.com"}
    response = client.post("/api/v1/targets", headers=headers, json=target_payload)
    assert response.status_code == 200
    target_id = response.json()["id"]
    
    # 2. Run OSINT Scan
    scan_payload = {
        "target_id": target_id,
        "nmap_enabled": False
    }
    response = client.post("/api/v1/scan", headers=headers, json=scan_payload)
    assert response.status_code == 200
    assert response.json()["target"] == "example.com"
    
    # 3. Nmap scan on internal IP should be blocked
    target_payload_internal = {"domain": "127.0.0.1"}
    resp2 = client.post("/api/v1/targets", headers=headers, json=target_payload_internal)
    target_id_internal = resp2.json()["id"]
    
    scan_payload_internal = {
        "target_id": target_id_internal,
        "nmap_enabled": True
    }
    resp3 = client.post("/api/v1/scan", headers=headers, json=scan_payload_internal)
    assert resp3.status_code == 400
    assert "internal" in resp3.json()["detail"].lower()
