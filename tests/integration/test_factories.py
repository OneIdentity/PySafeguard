"""Integration tests: factory functions from pysafeguard.__init__."""

import pytest

import pysafeguard
from pysafeguard import HttpMethods, PySafeguardConnection, Services
from pysafeguard.async_connection import AsyncConnection
from pysafeguard.connection import Connection

pytestmark = pytest.mark.integration


# ===========================================================================
# Sync factories
# ===========================================================================


class TestConnectPassword:
    def test_returns_authenticated_connection(self, spp_host, spp_username, spp_password, spp_verify):
        conn = pysafeguard.connect_password(spp_host, spp_username, spp_password, verify=spp_verify)
        assert isinstance(conn, PySafeguardConnection)
        assert conn.UserToken is not None
        resp = conn.invoke(HttpMethods.GET, Services.CORE, "Me")
        assert resp.status_code == 200


class TestConnectToken:
    def test_reuses_existing_token(self, sync_connection, spp_host, spp_verify):
        token = sync_connection.UserToken
        conn = pysafeguard.connect_token(spp_host, token, verify=spp_verify)
        assert isinstance(conn, PySafeguardConnection)
        resp = conn.invoke(HttpMethods.GET, Services.CORE, "Me")
        assert resp.status_code == 200


class TestConnectAnonymous:
    def test_can_access_notification_status(self, spp_host, spp_verify):
        conn = pysafeguard.connect_anonymous(spp_host, verify=spp_verify)
        assert isinstance(conn, PySafeguardConnection)
        assert conn.UserToken is None
        resp = conn.invoke(HttpMethods.GET, Services.NOTIFICATION, "Status")
        assert resp.status_code == 200


# ===========================================================================
# Async factories
# ===========================================================================


class TestAsyncConnectPassword:
    @pytest.mark.asyncio
    async def test_returns_authenticated_connection(self, spp_host, spp_username, spp_password, spp_verify):
        conn = await pysafeguard.async_connect_password(spp_host, spp_username, spp_password, verify=spp_verify)
        assert isinstance(conn, AsyncConnection)
        assert conn.UserToken is not None
        resp = await conn.invoke(HttpMethods.GET, Services.CORE, "Me")
        assert resp.status == 200


class TestAsyncConnectToken:
    @pytest.mark.asyncio
    async def test_reuses_existing_token(self, async_connection, spp_host, spp_verify):
        token = async_connection.UserToken
        conn = pysafeguard.async_connect_token(spp_host, token, verify=spp_verify)
        assert isinstance(conn, AsyncConnection)
        resp = await conn.invoke(HttpMethods.GET, Services.CORE, "Me")
        assert resp.status == 200


class TestAsyncConnectAnonymous:
    @pytest.mark.asyncio
    async def test_can_access_notification_status(self, spp_host, spp_verify):
        conn = pysafeguard.async_connect_anonymous(spp_host, verify=spp_verify)
        assert isinstance(conn, AsyncConnection)
        resp = await conn.invoke(HttpMethods.GET, Services.NOTIFICATION, "Status")
        assert resp.status == 200
