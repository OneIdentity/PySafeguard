"""Unit tests for AsyncConnection logic using mocked HTTP responses.

The async Connection uses a lazy ``_get_session()`` method that returns a
persistent ``aiohttp.ClientSession``.  Tests patch ``_get_session`` to inject
a mock session whose ``request`` method returns prepared fake responses.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pysafeguard.async_connection import AsyncConnection, AsyncWebRequestError
from pysafeguard.data_types import HttpMethods, Services


_HTTP_REASONS = {200: "OK", 201: "Created", 204: "No Content", 400: "Bad Request", 404: "Not Found", 500: "Internal Server Error"}


def _make_async_response(status=200, json_data=None, headers=None, content_type="application/json; charset=utf-8"):
    """Build a fake aiohttp.ClientResponse-like object.

    Default content-type matches the real Safeguard appliance which always
    returns ``application/json; charset=utf-8``.
    """
    resp = MagicMock()
    resp.status = status
    resp.headers = {"content-type": content_type, **(headers or {})}
    resp.json = AsyncMock(return_value=json_data)
    resp.read = AsyncMock(return_value=json.dumps(json_data).encode() if json_data else b"")
    resp.reason = _HTTP_REASONS.get(status, "Unknown")
    resp.url = "https://host/fake"
    resp.method = "GET"
    return resp


def _mock_session_with_responses(*responses):
    """Create a mock aiohttp session that yields the given responses in order.

    Each call to ``session.request(...)`` returns an awaitable that resolves
    to the next response.
    """
    it = iter(responses)
    session = MagicMock()
    session.request = AsyncMock(side_effect=lambda *a, **kw: next(it))
    session.closed = False
    return session


class TestAsyncInvokeUrlConstruction:
    @pytest.mark.asyncio
    async def test_rsts_no_api_version(self):
        """RSTS service should NOT include the API version in the path."""
        resp = _make_async_response()
        session = _mock_session_with_responses(resp)

        conn = AsyncConnection("host", verify=False)
        with patch.object(conn, "_get_session", return_value=session):
            await conn.invoke(HttpMethods.POST, Services.RSTS, "oauth2/token")

        url = session.request.call_args[0][1]
        assert "v4" not in url
        assert "RSTS" in url
        assert "oauth2/token" in url


class TestAsyncConnectPassword:
    @pytest.mark.asyncio
    async def test_successful_auth_sets_token(self):
        """Simulate the two-step auth: RSTS → LoginResponse."""
        rsts_resp = _make_async_response(
            200,
            {
                "access_token": "rsts-token",
                "expires_in": 299,
                "scope": "rsts:sts:primaryproviderid:local:pwd",
                "success": True,
                "token_type": "Bearer",
            },
        )
        login_resp = _make_async_response(
            200,
            {
                "Status": "Success",
                "UserToken": "user-token-456",
                "PrimaryProviderId": None,
                "SecondaryProviderId": None,
                "WebClientInactivityTimeout": 15,
                "DesktopClientInactivityTimeout": 1440,
            },
        )
        session = _mock_session_with_responses(rsts_resp, login_resp)

        conn = AsyncConnection("host", verify=False)
        with patch.object(conn, "_get_session", return_value=session):
            await conn.connect_password("admin", "pass")
        assert conn.UserToken == "user-token-456"

    @pytest.mark.asyncio
    async def test_rsts_failure_raises(self):
        error_resp = _make_async_response(
            400,
            json_data={"error": "invalid_request", "error_description": "Access denied.", "success": False},
        )
        session = _mock_session_with_responses(error_resp)

        conn = AsyncConnection("host", verify=False)
        with patch.object(conn, "_get_session", return_value=session):
            with pytest.raises(AsyncWebRequestError):
                await conn.connect_password("admin", "wrong")


class TestAsyncA2AValidation:
    @pytest.mark.asyncio
    async def test_empty_api_key_raises(self):
        with pytest.raises(Exception, match="apiKey may not be null or empty"):
            await AsyncConnection.a2a_get_credential("host", "", "cert.pem", "key.pem")

    @pytest.mark.asyncio
    async def test_empty_cert_and_key_raises(self):
        with pytest.raises(Exception, match="cert path and key path may not be null or empty"):
            await AsyncConnection.a2a_get_credential("host", "my-key", "", "")
