"""Tests for SafeguardClient construction and properties.

Covers init defaults, repr, is_authenticated, context manager behavior,
and basic lifecycle (login/logout) with mocked auth.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from requests import Session

from pysafeguard.auth import TokenAuth
from pysafeguard.client import SafeguardClient
from pysafeguard.errors import SafeguardError


class TestSafeguardClientInit:
    def test_default_attributes(self):
        client = SafeguardClient("myhost")
        assert client.host == "myhost"
        assert client.user_token is None
        assert client.api_version == "v4"
        assert client.verify is True
        assert client.auto_refresh is False
        assert client.is_authenticated is False
        client.close()

    def test_custom_verify_false(self):
        client = SafeguardClient("host", verify=False)
        assert client.verify is False
        client.close()

    def test_custom_verify_path(self):
        client = SafeguardClient("host", verify="/path/to/ca.pem")
        assert client.verify == "/path/to/ca.pem"
        client.close()

    def test_custom_api_version(self):
        client = SafeguardClient("host", api_version="v3")
        assert client.api_version == "v3"
        client.close()

    def test_custom_timeout(self):
        client = SafeguardClient("host", timeout=60)
        assert client._timeout == 60
        client.close()

    def test_auto_refresh(self):
        client = SafeguardClient("host", auto_refresh=True)
        assert client.auto_refresh is True
        client.close()


class TestSafeguardClientRepr:
    def test_repr_unauthenticated(self):
        client = SafeguardClient("host")
        r = repr(client)
        assert "host" in r
        assert "not authenticated" in r
        assert "None" in r  # auth type
        client.close()

    def test_repr_with_auth(self):
        client = SafeguardClient("host", auth=TokenAuth("tok"))
        r = repr(client)
        assert "TokenAuth" in r
        assert "not authenticated" in r
        client.close()


class TestSafeguardClientLifecycle:
    def test_login_without_auth_raises(self):
        client = SafeguardClient("host")
        with pytest.raises(SafeguardError, match="No auth strategy"):
            client.login()
        client.close()

    def test_login_with_token_auth(self):
        client = SafeguardClient("host", auth=TokenAuth("my-token"))
        client.login()
        assert client.is_authenticated is True
        assert client.user_token == "my-token"
        client.close()

    def test_logout_without_login_is_noop(self):
        client = SafeguardClient("host")
        client.logout()  # should not raise
        client.close()

    def test_refresh_without_auth_raises(self):
        client = SafeguardClient("host")
        with pytest.raises(SafeguardError, match="No auth strategy"):
            client.refresh_access_token()
        client.close()

    def test_refresh_with_non_refreshable_auth_raises(self):
        client = SafeguardClient("host", auth=TokenAuth("tok"))
        client.login()
        with pytest.raises(SafeguardError, match="does not support"):
            client.refresh_access_token()
        client.close()


class TestSafeguardClientContextManager:
    def test_context_manager_with_auth(self):
        with patch.object(Session, "request", return_value=MagicMock(status_code=200)):
            with SafeguardClient("host", auth=TokenAuth("tok")) as client:
                assert client.is_authenticated is True
                assert client.user_token == "tok"

    def test_context_manager_without_auth(self):
        with SafeguardClient("host") as client:
            assert client.is_authenticated is False


class TestAsyncSafeguardClientInit:
    def test_default_attributes(self):
        from pysafeguard.async_client import AsyncSafeguardClient

        client = AsyncSafeguardClient("myhost")
        assert client.host == "myhost"
        assert client.user_token is None
        assert client.api_version == "v4"
        assert client.verify is True
        assert client.auto_refresh is False
        assert client.is_authenticated is False

    def test_repr(self):
        from pysafeguard.async_client import AsyncSafeguardClient

        client = AsyncSafeguardClient("host", auth=TokenAuth("tok"))
        r = repr(client)
        assert "AsyncSafeguardClient" in r
        assert "TokenAuth" in r

    @pytest.mark.asyncio
    async def test_login_without_auth_raises(self):
        from pysafeguard.async_client import AsyncSafeguardClient

        client = AsyncSafeguardClient("host")
        with pytest.raises(SafeguardError, match="No auth strategy"):
            await client.login()
        await client.close()

    @pytest.mark.asyncio
    async def test_login_with_token_auth(self):
        from pysafeguard.async_client import AsyncSafeguardClient

        client = AsyncSafeguardClient("host", auth=TokenAuth("my-token"))
        await client.login()
        assert client.is_authenticated is True
        assert client.user_token == "my-token"
        await client.close()
