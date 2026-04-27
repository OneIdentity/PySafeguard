"""Unit tests for AsyncConnection logic using mocked HTTP responses."""

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


class TestAsyncInvokeUrlConstruction:
    @pytest.mark.asyncio
    @patch("pysafeguard.async_connection.SSLContext")
    @patch("pysafeguard.async_connection.ClientSession")
    async def test_rsts_no_api_version(self, mock_session_cls, _mock_ssl):
        """RSTS service should NOT include the API version in the path."""
        resp = _make_async_response()
        captured_args: list[tuple[object, ...]] = []

        def mock_request(*args, **kwargs):
            captured_args.append(args)
            ctx = AsyncMock()
            ctx.__aenter__.return_value = resp
            ctx.__aexit__.return_value = False
            return ctx

        session_instance = MagicMock()
        session_instance.request = mock_request
        session_ctx = MagicMock()
        session_ctx.__aenter__ = AsyncMock(return_value=session_instance)
        session_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session_cls.return_value = session_ctx

        conn = AsyncConnection("host", verify=False)
        await conn.invoke(HttpMethods.POST, Services.RSTS, "oauth2/token")
        url = captured_args[0][1]
        assert "v4" not in url
        assert "RSTS" in url
        assert "oauth2/token" in url


class TestAsyncConnectPassword:
    @pytest.mark.asyncio
    @patch("pysafeguard.async_connection.SSLContext")
    @patch("pysafeguard.async_connection.ClientSession")
    async def test_successful_auth_sets_token(self, mock_session_cls, _mock_ssl):
        """Simulate the two-step auth: RSTS → LoginResponse."""
        rsts_resp = _make_async_response(200, {
            "access_token": "rsts-token",
            "expires_in": 299,
            "scope": "rsts:sts:primaryproviderid:local:pwd",
            "success": True,
            "token_type": "Bearer",
        })
        login_resp = _make_async_response(200, {
            "Status": "Success",
            "UserToken": "user-token-456",
            "PrimaryProviderId": None,
            "SecondaryProviderId": None,
            "WebClientInactivityTimeout": 15,
            "DesktopClientInactivityTimeout": 1440,
        })
        responses = iter([rsts_resp, login_resp])

        def mock_request(*args, **kwargs):
            ctx = AsyncMock()
            ctx.__aenter__.return_value = next(responses)
            ctx.__aexit__.return_value = False
            return ctx

        session_instance = MagicMock()
        session_instance.request = mock_request
        session_ctx = MagicMock()
        session_ctx.__aenter__ = AsyncMock(return_value=session_instance)
        session_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session_cls.return_value = session_ctx

        conn = AsyncConnection("host", verify=False)
        await conn.connect_password("admin", "pass")
        assert conn.UserToken == "user-token-456"

    @pytest.mark.asyncio
    @patch("pysafeguard.async_connection.SSLContext")
    @patch("pysafeguard.async_connection.ClientSession")
    async def test_rsts_failure_raises(self, mock_session_cls, _mock_ssl):
        error_resp = _make_async_response(
            400,
            json_data={"error": "invalid_request", "error_description": "Access denied.", "success": False},
        )

        def mock_request(*args, **kwargs):
            ctx = AsyncMock()
            ctx.__aenter__.return_value = error_resp
            ctx.__aexit__.return_value = False
            return ctx

        session_instance = MagicMock()
        session_instance.request = mock_request
        session_ctx = MagicMock()
        session_ctx.__aenter__ = AsyncMock(return_value=session_instance)
        session_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session_cls.return_value = session_ctx

        conn = AsyncConnection("host", verify=False)
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
