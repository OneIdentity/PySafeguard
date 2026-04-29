# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Integration tests: async authentication flows against a live appliance."""

import pytest

from pysafeguard import ApiError, AsyncSafeguardClient, PasswordAuth, Service, TokenAuth

pytestmark = pytest.mark.integration


class TestAsyncPasswordAuth:
    @pytest.mark.asyncio
    async def test_connect_password_succeeds(self, spp_host, spp_username, spp_password, spp_verify):
        client = AsyncSafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        await client.login()
        assert client.user_token is not None
        assert len(client.user_token) > 0
        assert "Bearer" in client._headers.get("authorization", "")

    @pytest.mark.asyncio
    async def test_connect_password_bad_credentials(self, spp_host, spp_verify):
        client = AsyncSafeguardClient(
            spp_host,
            auth=PasswordAuth("local", "nonexistent_user_xyz", "wrong_password"),
            verify=spp_verify,
        )
        with pytest.raises((ApiError, Exception)):
            await client.login()


class TestAsyncTokenAuth:
    @pytest.mark.asyncio
    async def test_connect_token_reuse(self, async_connection, spp_host, spp_verify):
        """Authenticate, extract token, create new connection, use token."""
        token = async_connection.user_token
        assert token is not None

        client2 = AsyncSafeguardClient(
            spp_host,
            auth=TokenAuth(token),
            verify=spp_verify,
        )
        await client2.login()
        resp = await client2.get(Service.CORE, "Me")
        assert resp.status == 200
