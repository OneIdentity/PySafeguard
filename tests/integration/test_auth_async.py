"""Integration tests: async authentication flows against a live appliance."""

import pytest

from pysafeguard.async_connection import AsyncConnection, AsyncWebRequestError

pytestmark = pytest.mark.integration


class TestAsyncPasswordAuth:
    @pytest.mark.asyncio
    async def test_connect_password_succeeds(self, spp_host, spp_username, spp_password, spp_verify):
        conn = AsyncConnection(spp_host, spp_verify)
        await conn.connect_password(spp_username, spp_password)
        assert conn.UserToken is not None
        assert len(conn.UserToken) > 0
        assert "Bearer" in conn.headers.get("authorization", "")

    @pytest.mark.asyncio
    async def test_connect_password_bad_credentials(self, spp_host, spp_verify):
        conn = AsyncConnection(spp_host, spp_verify)
        with pytest.raises((AsyncWebRequestError, Exception)):
            await conn.connect_password("nonexistent_user_xyz", "wrong_password")


class TestAsyncTokenAuth:
    @pytest.mark.asyncio
    async def test_connect_token_reuse(self, async_connection, spp_host, spp_verify):
        """Authenticate, extract token, create new connection, use token."""
        from pysafeguard.data_types import HttpMethods, Services

        token = async_connection.UserToken
        assert token is not None

        conn2 = AsyncConnection(spp_host, spp_verify)
        conn2.connect_token(token)
        resp = await conn2.invoke(HttpMethods.GET, Services.CORE, "Me")
        assert resp.status == 200
