import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from app.core.config import settings
from app.services.osint.osint_service import CensysService


@pytest.mark.asyncio
async def test_censys_service_without_credentials_returns_mock_data():
    """When no PAT or legacy credentials are configured, CensysService falls back to realistic mock data."""
    with patch.object(settings, "CENSYS_PAT", ""), \
         patch.object(settings, "CENSYS_API_KEY", ""), \
         patch.object(settings, "CENSYS_API_ID", ""), \
         patch.object(settings, "CENSYS_API_SECRET", ""):
        data = await CensysService.search_host("192.168.1.100")
        assert data["ip"] == "192.168.1.100"
        assert "services" in data
        assert isinstance(data["services"], list)
        assert "ports" in data


@pytest.mark.asyncio
async def test_censys_service_with_pat_calls_platform_v3_api():
    """When CENSYS_PAT is configured, CensysService uses Bearer token and Platform API v3."""
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={
        "code": 200,
        "status": "OK",
        "result": {
            "host": {
                "ip": "8.8.8.8",
                "last_updated_at": "2026-10-01T12:00:00Z",
                "location": {
                    "country": "United States",
                    "city": "Mountain View",
                    "coordinates": {"latitude": 37.4, "longitude": -122.0}
                },
                "autonomous_system": {
                    "asn": 15169,
                    "name": "GOOGLE",
                    "description": "Google LLC"
                },
                "operating_system": {
                    "product": "Linux",
                    "version": "5.4"
                },
                "services": [
                    {
                        "port": 443,
                        "transport_protocol": "TCP",
                        "service_name": "HTTP",
                        "software": [{"product": "nginx", "version": "1.25.0"}],
                        "banner": "HTTP/1.1 200 OK",
                        "tls": {
                            "certificate": {
                                "fingerprint_sha256": "abcdef123456",
                                "leaf_data": {
                                    "issuer_dn": "CN=GTS CA 1C3",
                                    "subject_dn": "CN=dns.google",
                                    "validity": {"end": "2026-12-31T23:59:59Z"}
                                }
                            }
                        }
                    },
                    {
                        "port": 53,
                        "transport_protocol": "UDP",
                        "service_name": "DNS",
                        "software": [],
                        "banner": ""
                    }
                ]
            }
        }
    })

    captured_url = None
    captured_headers = None

    class MockContextManager:
        async def __aenter__(self):
            return mock_response
        async def __aexit__(self, *args):
            return None

    class MockSession:
        def get(self, url, headers=None, timeout=None):
            nonlocal captured_url, captured_headers
            captured_url = url
            captured_headers = headers
            return MockContextManager()

        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None

    with patch.object(settings, "CENSYS_PAT", "censys_test_pat_token_xyz"), \
         patch("aiohttp.ClientSession", return_value=MockSession()):
        data = await CensysService.search_host("8.8.8.8")

    assert captured_url == "https://api.platform.censys.io/v3/global/asset/host/8.8.8.8"
    assert captured_headers["Authorization"] == "Bearer censys_test_pat_token_xyz"
    assert "application/vnd.censys.api.v3.host.v1+json" in captured_headers["Accept"]

    assert data["ip"] == "8.8.8.8"
    assert data["service_count"] == 2
    assert 443 in data["ports"]
    assert 53 in data["ports"]
    assert data["country"] == "United States"
    assert data["asn"] == 15169
    assert data["as_name"] == "GOOGLE"
    assert data["os"] == "Linux"
    assert data["services"][0]["product"] == "nginx"
    assert data["services"][0]["tls"]["issuer"] == "CN=GTS CA 1C3"
    assert data["services"][0]["tls"]["fingerprint"] == "abcdef123456"


@pytest.mark.asyncio
async def test_censys_service_with_censys_api_key_alias():
    """CENSYS_API_KEY acts as an alias for CENSYS_PAT."""
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={
        "result": {
            "services": [{"port": 80, "service_name": "HTTP"}],
            "location": {"country": "Germany"}
        }
    })

    captured_headers = None

    class MockContextManager:
        async def __aenter__(self):
            return mock_response
        async def __aexit__(self, *args):
            return None

    class MockSession:
        def get(self, url, headers=None, timeout=None):
            nonlocal captured_headers
            captured_headers = headers
            return MockContextManager()

        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None

    with patch.object(settings, "CENSYS_PAT", ""), \
         patch.object(settings, "CENSYS_API_KEY", "alias_pat_token_123"), \
         patch("aiohttp.ClientSession", return_value=MockSession()):
        data = await CensysService.search_host("1.2.3.4")

    assert captured_headers["Authorization"] == "Bearer alias_pat_token_123"
    assert data["country"] == "Germany"
    assert 80 in data["ports"]


@pytest.mark.asyncio
async def test_censys_service_handles_auth_error():
    """Returns friendly auth error message on 401/403."""
    mock_response = MagicMock()
    mock_response.status = 401

    class MockContextManager:
        async def __aenter__(self):
            return mock_response
        async def __aexit__(self, *args):
            return None

    class MockSession:
        def get(self, url, headers=None, timeout=None):
            return MockContextManager()

        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None

    with patch.object(settings, "CENSYS_PAT", "invalid_pat"), \
         patch("aiohttp.ClientSession", return_value=MockSession()):
        data = await CensysService.search_host("8.8.8.8")

    assert "error" in data
    assert "401" in data["error"]
    assert "PAT" in data["error"]


@pytest.mark.asyncio
async def test_censys_service_legacy_fallback():
    """Falls back to Basic auth if only legacy CENSYS_API_ID and CENSYS_API_SECRET are provided."""
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={
        "result": {
            "services": [{"port": 22, "service_name": "SSH"}],
        }
    })

    captured_url = None
    captured_headers = None

    class MockContextManager:
        async def __aenter__(self):
            return mock_response
        async def __aexit__(self, *args):
            return None

    class MockSession:
        def get(self, url, headers=None, timeout=None):
            nonlocal captured_url, captured_headers
            captured_url = url
            captured_headers = headers
            return MockContextManager()

        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None

    with patch.object(settings, "CENSYS_PAT", ""), \
         patch.object(settings, "CENSYS_API_KEY", ""), \
         patch.object(settings, "CENSYS_API_ID", "legacy_id"), \
         patch.object(settings, "CENSYS_API_SECRET", "legacy_secret"), \
         patch("aiohttp.ClientSession", return_value=MockSession()):
        data = await CensysService.search_host("1.1.1.1")

    assert captured_url == "https://search.censys.io/api/v2/hosts/1.1.1.1"
    assert captured_headers["Authorization"].startswith("Basic ")
    assert 22 in data["ports"]
