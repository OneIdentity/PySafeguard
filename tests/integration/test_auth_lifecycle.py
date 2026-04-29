# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Integration tests: auth lifecycle — refresh, logout, credential storage, context manager."""

import pytest

from pysafeguard import (
    AsyncSafeguardClient,
    PasswordAuth,
    SafeguardClient,
    Service,
    TokenAuth,
)
from pysafeguard.errors import SafeguardError

pytestmark = pytest.mark.integration


# ===========================================================================
# Sync
# ===========================================================================


class TestSyncRefreshAccessToken:
    def test_refresh_after_password_auth(self, spp_host, spp_username, spp_password, spp_verify):
        """After password auth, refresh should obtain a new valid token."""
        client = SafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        client.login()
        original_token = client.user_token

        client.refresh_access_token()
        assert client.user_token is not None
        assert client.user_token != original_token

        # New token should work
        resp = client.get(Service.CORE, "Me")
        assert resp.status_code == 200

    def test_refresh_with_bare_token_raises(self, spp_host, spp_verify):
        """TokenAuth cannot refresh, so refresh should fail."""
        client = SafeguardClient(
            spp_host,
            auth=TokenAuth("fake-token-that-wont-refresh"),
            verify=spp_verify,
        )
        with pytest.raises(SafeguardError):
            client.refresh_access_token()


class TestSyncLogout:
    def test_logout_invalidates_token(self, spp_host, spp_username, spp_password, spp_verify):
        client = SafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        client.login()
        assert client.user_token is not None

        client.logout()
        assert client.user_token is None
        assert "authorization" not in client._headers

    def test_logout_then_refresh(self, spp_host, spp_username, spp_password, spp_verify):
        """After logout, refresh should still work because credentials are preserved."""
        client = SafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        client.login()
        client.logout()
        assert client.user_token is None

        client.refresh_access_token()
        assert client.user_token is not None

        resp = client.get(Service.CORE, "Me")
        assert resp.status_code == 200

    def test_logout_noop_when_no_token(self, spp_host, spp_verify):
        client = SafeguardClient(spp_host, verify=spp_verify)
        client.logout()  # Should not raise


class TestSyncContextManager:
    def test_with_statement(self, spp_host, spp_username, spp_password, spp_verify):
        with SafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        ) as client:
            resp = client.get(Service.CORE, "Me")
            assert resp.status_code == 200


class TestSyncCredentialStorage:
    def test_password_auth_stored(self, spp_host, spp_username, spp_password, spp_verify):
        client = SafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        client.login()
        assert client._auth is not None
        assert isinstance(client._auth, PasswordAuth)

    def test_token_auth_cannot_refresh(self, sync_connection, spp_host, spp_verify):
        """TokenAuth has can_refresh=False, so refresh raises."""
        token = sync_connection.user_token
        client = SafeguardClient(
            spp_host,
            auth=TokenAuth(token),
            verify=spp_verify,
        )
        client.login()
        with pytest.raises(SafeguardError):
            client.refresh_access_token()


class TestSyncTokenLifetimeAfterRefresh:
    def test_token_lifetime_positive_after_refresh(self, spp_host, spp_username, spp_password, spp_verify):
        client = SafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        client.login()
        client.refresh_access_token()
        remaining = client.token_lifetime_remaining
        assert remaining is not None
        assert remaining > 0


# ===========================================================================
# Async
# ===========================================================================


class TestAsyncRefreshAccessToken:
    @pytest.mark.asyncio
    async def test_refresh_after_password_auth(self, spp_host, spp_username, spp_password, spp_verify):
        client = AsyncSafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        await client.login()
        original_token = client.user_token

        await client.refresh_access_token()
        assert client.user_token is not None
        assert client.user_token != original_token

        resp = await client.get(Service.CORE, "Me")
        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_refresh_with_bare_token_raises(self, spp_host, spp_verify):
        client = AsyncSafeguardClient(
            spp_host,
            auth=TokenAuth("fake-token"),
            verify=spp_verify,
        )
        with pytest.raises(SafeguardError):
            await client.refresh_access_token()


class TestAsyncLogout:
    @pytest.mark.asyncio
    async def test_logout_invalidates_token(self, spp_host, spp_username, spp_password, spp_verify):
        client = AsyncSafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        await client.login()
        await client.logout()
        assert client.user_token is None

    @pytest.mark.asyncio
    async def test_logout_then_refresh(self, spp_host, spp_username, spp_password, spp_verify):
        client = AsyncSafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        await client.login()
        await client.logout()

        await client.refresh_access_token()
        assert client.user_token is not None

        resp = await client.get(Service.CORE, "Me")
        assert resp.status == 200


class TestAsyncContextManager:
    @pytest.mark.asyncio
    async def test_async_with_statement(self, spp_host, spp_username, spp_password, spp_verify):
        async with AsyncSafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        ) as client:
            resp = await client.get(Service.CORE, "Me")
            assert resp.status == 200


class TestAsyncCredentialStorage:
    @pytest.mark.asyncio
    async def test_password_auth_stored(self, spp_host, spp_username, spp_password, spp_verify):
        client = AsyncSafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        await client.login()
        assert client._auth is not None
        assert isinstance(client._auth, PasswordAuth)
