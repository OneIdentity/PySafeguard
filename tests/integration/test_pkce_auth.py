"""Integration tests: PKCE authentication (sync + async).

PKCE is the recommended auth method for newer appliances where
Resource Owner Grant (ROG) is disabled by default.
"""

from __future__ import annotations

import pytest

from pysafeguard import (
    AsyncSafeguardClient,
    PkceAuth,
    SafeguardClient,
    Service,
)

pytestmark = pytest.mark.integration


# ===========================================================================
# Sync PKCE
# ===========================================================================


class TestSyncPkceAuth:
    def test_pkce_login_and_api_call(self, spp_host, spp_username, spp_password, spp_verify):
        """PkceAuth should authenticate and allow API calls."""
        auth = PkceAuth("local", spp_username, spp_password)
        client = SafeguardClient(spp_host, auth=auth, verify=spp_verify)
        client.login()

        assert client.is_authenticated
        assert client.user_token is not None

        resp = client.get(Service.CORE, "Me")
        assert resp.status_code == 200
        me = resp.json()
        assert me["Name"].lower() == spp_username.lower()

    def test_pkce_refresh(self, spp_host, spp_username, spp_password, spp_verify):
        """PkceAuth without MFA should support token refresh."""
        auth = PkceAuth("local", spp_username, spp_password)
        client = SafeguardClient(spp_host, auth=auth, verify=spp_verify)
        client.login()
        original_token = client.user_token

        client.refresh_access_token()
        assert client.user_token is not None
        assert client.user_token != original_token

        resp = client.get(Service.CORE, "Me")
        assert resp.status_code == 200

    def test_pkce_context_manager(self, spp_host, spp_username, spp_password, spp_verify):
        """PKCE auth should work with context manager pattern."""
        auth = PkceAuth("local", spp_username, spp_password)
        with SafeguardClient(spp_host, auth=auth, verify=spp_verify) as client:
            resp = client.get(Service.CORE, "Me")
            assert resp.status_code == 200


# ===========================================================================
# Async PKCE
# ===========================================================================


class TestAsyncPkceAuth:
    @pytest.mark.asyncio
    async def test_pkce_login_and_api_call(self, spp_host, spp_username, spp_password, spp_verify):
        """Async PkceAuth should authenticate and allow API calls."""
        auth = PkceAuth("local", spp_username, spp_password)
        client = AsyncSafeguardClient(spp_host, auth=auth, verify=spp_verify)
        await client.login()

        assert client.is_authenticated
        assert client.user_token is not None

        resp = await client.get(Service.CORE, "Me")
        assert resp.status == 200
        me = await resp.json()
        assert me["Name"].lower() == spp_username.lower()
        await client.close()

    @pytest.mark.asyncio
    async def test_pkce_refresh(self, spp_host, spp_username, spp_password, spp_verify):
        """Async PkceAuth should support token refresh."""
        auth = PkceAuth("local", spp_username, spp_password)
        client = AsyncSafeguardClient(spp_host, auth=auth, verify=spp_verify)
        await client.login()
        original_token = client.user_token

        await client.refresh_access_token()
        assert client.user_token is not None
        assert client.user_token != original_token

        resp = await client.get(Service.CORE, "Me")
        assert resp.status == 200
        await client.close()
