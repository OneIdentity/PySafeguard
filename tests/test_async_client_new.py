"""Tests for AsyncSafeguardClient request logic using mocked HTTP responses.

Tests URL construction, auth flow, and verb methods using the new v8.0
async API surface.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pysafeguard.async_client import AsyncSafeguardClient
from pysafeguard.auth import TokenAuth
from pysafeguard.data_types import HttpMethod, Service
from pysafeguard.errors import SafeguardError


_HTTP_REASONS = {200: "OK", 400: "Bad Request", 404: "Not Found"}


def _make_async_response(status=200, json_data=None, headers=None, content_type="application/json; charset=utf-8"):
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
    it = iter(responses)
    session = MagicMock()
    session.request = AsyncMock(side_effect=lambda *a, **kw: next(it))
    session.closed = False
    return session


class TestAsyncClientRequestUrl:
    @pytest.mark.asyncio
    async def test_rsts_no_api_version(self):
        resp = _make_async_response()
        session = _mock_session_with_responses(resp)
        client = AsyncSafeguardClient("host", verify=False)
        with patch.object(client, "_get_session", AsyncMock(return_value=session)):
            await client.request(HttpMethod.POST, Service.RSTS, "oauth2/token")
        url = session.request.call_args[0][1]
        assert "v4" not in url
        assert "RSTS" in url

    @pytest.mark.asyncio
    async def test_core_endpoint(self):
        resp = _make_async_response()
        session = _mock_session_with_responses(resp)
        client = AsyncSafeguardClient("host", auth=TokenAuth("tok"))
        await client.login()
        with patch.object(client, "_get_session", AsyncMock(return_value=session)):
            await client.get(Service.CORE, "Users")
        url = session.request.call_args[0][1]
        assert "service/core/v4/Users" in url


class TestAsyncClientVerbMethods:
    @pytest.mark.asyncio
    async def test_post(self):
        resp = _make_async_response()
        session = _mock_session_with_responses(resp)
        client = AsyncSafeguardClient("host")
        with patch.object(client, "_get_session", AsyncMock(return_value=session)):
            await client.post(Service.CORE, "Users", json={"Name": "Test"})
        assert session.request.call_args[0][0] == "POST"

    @pytest.mark.asyncio
    async def test_put(self):
        resp = _make_async_response()
        session = _mock_session_with_responses(resp)
        client = AsyncSafeguardClient("host")
        with patch.object(client, "_get_session", AsyncMock(return_value=session)):
            await client.put(Service.CORE, "Users/1", json={"Name": "Updated"})
        assert session.request.call_args[0][0] == "PUT"

    @pytest.mark.asyncio
    async def test_delete(self):
        resp = _make_async_response()
        session = _mock_session_with_responses(resp)
        client = AsyncSafeguardClient("host")
        with patch.object(client, "_get_session", AsyncMock(return_value=session)):
            await client.delete(Service.CORE, "Users/1")
        assert session.request.call_args[0][0] == "DELETE"


class TestAsyncClientLifecycle:
    @pytest.mark.asyncio
    async def test_login_without_auth_raises(self):
        client = AsyncSafeguardClient("host")
        with pytest.raises(SafeguardError, match="No auth strategy"):
            await client.login()
        await client.close()

    @pytest.mark.asyncio
    async def test_login_with_token_auth(self):
        client = AsyncSafeguardClient("host", auth=TokenAuth("my-token"))
        await client.login()
        assert client.is_authenticated is True
        assert client.user_token == "my-token"
        await client.close()

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        from unittest.mock import AsyncMock

        from pysafeguard.async_client import AsyncSafeguardClient

        client = AsyncSafeguardClient("host", auth=TokenAuth("tok"))
        # Mock _get_session to avoid real HTTP for logout
        mock_session = MagicMock()
        mock_session.request = AsyncMock(return_value=MagicMock(status=200, read=AsyncMock(return_value=b"")))
        mock_session.closed = False
        mock_session.close = AsyncMock()
        client._session = mock_session

        async with client:
            assert client.is_authenticated is True
