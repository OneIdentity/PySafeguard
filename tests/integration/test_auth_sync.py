# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Integration tests: sync authentication flows against a live appliance."""

import pytest

from pysafeguard import ApiError, PasswordAuth, SafeguardClient, Service, TokenAuth

pytestmark = pytest.mark.integration


class TestPasswordAuth:
    def test_connect_password_succeeds(self, spp_host, spp_username, spp_password, spp_verify):
        client = SafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        client.login()
        assert client.user_token is not None
        assert len(client.user_token) > 0
        assert "Bearer" in client._headers.get("authorization", "")

    def test_connect_password_bad_credentials(self, spp_host, spp_verify):
        client = SafeguardClient(
            spp_host,
            auth=PasswordAuth("local", "nonexistent_user_xyz", "wrong_password"),
            verify=spp_verify,
        )
        with pytest.raises((ApiError, Exception)):
            client.login()


class TestTokenAuth:
    def test_connect_token_reuse(self, sync_connection, spp_host, spp_verify):
        """Authenticate, extract token, create new connection, use token."""
        token = sync_connection.user_token
        assert token is not None

        client2 = SafeguardClient(
            spp_host,
            auth=TokenAuth(token),
            verify=spp_verify,
        )
        client2.login()
        resp = client2.get(Service.CORE, "Me")
        assert resp.status_code == 200


class TestMeEndpoint:
    def test_get_me(self, sync_connection):
        """Verify the authenticated user can retrieve their own profile."""
        resp = sync_connection.get(Service.CORE, "Me")
        assert resp.status_code == 200
        data = resp.json()
        assert "Id" in data
        assert "Name" in data
