"""Integration tests: sync authentication flows against a live appliance."""

import pytest

from pysafeguard import HttpMethods, PySafeguardConnection, Services, WebRequestError

pytestmark = pytest.mark.integration


class TestPasswordAuth:
    def test_connect_password_succeeds(self, spp_host, spp_username, spp_password, spp_verify):
        conn = PySafeguardConnection(spp_host, spp_verify)
        conn.connect_password(spp_username, spp_password)
        assert conn.UserToken is not None
        assert len(conn.UserToken) > 0
        assert "Bearer" in conn.headers.get("authorization", "")

    def test_connect_password_bad_credentials(self, spp_host, spp_verify):
        conn = PySafeguardConnection(spp_host, spp_verify)
        with pytest.raises((WebRequestError, Exception)):
            conn.connect_password("nonexistent_user_xyz", "wrong_password")


class TestTokenAuth:
    def test_connect_token_reuse(self, sync_connection, spp_host, spp_verify):
        """Authenticate, extract token, create new connection, use token."""
        token = sync_connection.UserToken
        assert token is not None

        conn2 = PySafeguardConnection(spp_host, spp_verify)
        conn2.connect_token(token)
        resp = conn2.invoke(HttpMethods.GET, Services.CORE, "Me")
        assert resp.status_code == 200


class TestMeEndpoint:
    def test_get_me(self, sync_connection):
        """Verify the authenticated user can retrieve their own profile."""
        resp = sync_connection.invoke(HttpMethods.GET, Services.CORE, "Me")
        assert resp.status_code == 200
        data = resp.json()
        assert "Id" in data
        assert "Name" in data
