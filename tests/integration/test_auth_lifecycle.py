"""Integration tests: auth lifecycle — refresh, logout, credential storage, context manager."""

import pytest

from pysafeguard import HttpMethods, PySafeguardConnection, Services
from pysafeguard.async_connection import AsyncConnection
from pysafeguard.connection import Connection
from pysafeguard.exceptions import SafeguardException

pytestmark = pytest.mark.integration


# ===========================================================================
# Sync
# ===========================================================================


class TestSyncRefreshAccessToken:
    def test_refresh_after_password_auth(self, spp_host, spp_username, spp_password, spp_verify):
        """After password auth, refresh should obtain a new valid token."""
        conn = Connection(spp_host, verify=spp_verify)
        conn.connect_password(spp_username, spp_password)
        original_token = conn.UserToken

        conn.refresh_access_token()
        assert conn.UserToken is not None
        assert conn.UserToken != original_token

        # New token should work
        resp = conn.invoke(HttpMethods.GET, Services.CORE, "Me")
        assert resp.status_code == 200

    def test_refresh_with_bare_token_raises(self, spp_host, spp_verify):
        """connect_token clears credentials, so refresh should fail."""
        conn = Connection(spp_host, verify=spp_verify)
        conn.connect_token("fake-token-that-wont-refresh")
        with pytest.raises(SafeguardException, match="No authentication credentials"):
            conn.refresh_access_token()


class TestSyncLogout:
    def test_logout_invalidates_token(self, spp_host, spp_username, spp_password, spp_verify):
        conn = Connection(spp_host, verify=spp_verify)
        conn.connect_password(spp_username, spp_password)
        assert conn.UserToken is not None

        conn.logout()
        assert conn.UserToken is None
        assert "authorization" not in conn.headers

    def test_logout_then_refresh(self, spp_host, spp_username, spp_password, spp_verify):
        """After logout, refresh should still work because credentials are preserved."""
        conn = Connection(spp_host, verify=spp_verify)
        conn.connect_password(spp_username, spp_password)
        conn.logout()
        assert conn.UserToken is None

        conn.refresh_access_token()
        assert conn.UserToken is not None

        resp = conn.invoke(HttpMethods.GET, Services.CORE, "Me")
        assert resp.status_code == 200

    def test_logout_noop_when_no_token(self, spp_host, spp_verify):
        conn = Connection(spp_host, verify=spp_verify)
        conn.logout()  # Should not raise


class TestSyncContextManager:
    def test_with_statement(self, spp_host, spp_username, spp_password, spp_verify):
        with Connection(spp_host, verify=spp_verify) as conn:
            conn.connect_password(spp_username, spp_password)
            resp = conn.invoke(HttpMethods.GET, Services.CORE, "Me")
            assert resp.status_code == 200


class TestSyncCredentialStorage:
    def test_password_credential_stored(self, spp_host, spp_username, spp_password, spp_verify):
        conn = Connection(spp_host, verify=spp_verify)
        conn.connect_password(spp_username, spp_password)
        assert conn._auth_credential is not None
        assert conn._auth_credential.username == spp_username
        assert conn._auth_credential.password.get_value() == spp_password

    def test_connect_token_clears_credential(self, sync_connection):
        """Switching to token auth should clear stored credentials."""
        token = sync_connection.UserToken
        sync_connection.connect_token(token)
        assert sync_connection._auth_credential is None

    def test_reauth_disposes_old_credential(self, spp_host, spp_username, spp_password, spp_verify):
        conn = Connection(spp_host, verify=spp_verify)
        conn.connect_password(spp_username, spp_password)
        old_hidden = conn._auth_credential.password

        conn.connect_password(spp_username, spp_password)
        assert old_hidden.is_disposed


class TestSyncTokenLifetimeAfterRefresh:
    def test_token_lifetime_positive_after_refresh(self, spp_host, spp_username, spp_password, spp_verify):
        conn = Connection(spp_host, verify=spp_verify)
        conn.connect_password(spp_username, spp_password)
        conn.refresh_access_token()
        remaining = conn.get_remaining_token_lifetime()
        assert remaining is not None
        assert remaining > 0


# ===========================================================================
# Async
# ===========================================================================


class TestAsyncRefreshAccessToken:
    @pytest.mark.asyncio
    async def test_refresh_after_password_auth(self, spp_host, spp_username, spp_password, spp_verify):
        conn = AsyncConnection(spp_host, verify=spp_verify)
        await conn.connect_password(spp_username, spp_password)
        original_token = conn.UserToken

        await conn.refresh_access_token()
        assert conn.UserToken is not None
        assert conn.UserToken != original_token

        resp = await conn.invoke(HttpMethods.GET, Services.CORE, "Me")
        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_refresh_with_bare_token_raises(self, spp_host, spp_verify):
        conn = AsyncConnection(spp_host, verify=spp_verify)
        conn.connect_token("fake-token")
        with pytest.raises(SafeguardException, match="No authentication credentials"):
            await conn.refresh_access_token()


class TestAsyncLogout:
    @pytest.mark.asyncio
    async def test_logout_invalidates_token(self, spp_host, spp_username, spp_password, spp_verify):
        conn = AsyncConnection(spp_host, verify=spp_verify)
        await conn.connect_password(spp_username, spp_password)
        await conn.logout()
        assert conn.UserToken is None

    @pytest.mark.asyncio
    async def test_logout_then_refresh(self, spp_host, spp_username, spp_password, spp_verify):
        conn = AsyncConnection(spp_host, verify=spp_verify)
        await conn.connect_password(spp_username, spp_password)
        await conn.logout()

        await conn.refresh_access_token()
        assert conn.UserToken is not None

        resp = await conn.invoke(HttpMethods.GET, Services.CORE, "Me")
        assert resp.status == 200


class TestAsyncContextManager:
    @pytest.mark.asyncio
    async def test_async_with_statement(self, spp_host, spp_username, spp_password, spp_verify):
        async with AsyncConnection(spp_host, verify=spp_verify) as conn:
            await conn.connect_password(spp_username, spp_password)
            resp = await conn.invoke(HttpMethods.GET, Services.CORE, "Me")
            assert resp.status == 200


class TestAsyncCredentialStorage:
    @pytest.mark.asyncio
    async def test_password_credential_stored(self, spp_host, spp_username, spp_password, spp_verify):
        conn = AsyncConnection(spp_host, verify=spp_verify)
        await conn.connect_password(spp_username, spp_password)
        assert conn._auth_credential is not None
        assert conn._auth_credential.username == spp_username
