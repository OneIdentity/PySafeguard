"""Integration tests: PersistentSafeguardEventListener.from_password live token factory.

Verifies the refactored from_password/from_certificate factory methods
that now use SafeguardClient + auth strategy objects instead of old Connection.
"""

from __future__ import annotations

import pytest

from pysafeguard.event import PersistentSafeguardEventListener

pytestmark = pytest.mark.integration


class TestPersistentFromPasswordLive:
    def test_token_factory_returns_valid_token(self, spp_host, spp_username, spp_password, spp_verify):
        """from_password token factory should produce a valid Safeguard user token."""
        listener = PersistentSafeguardEventListener.from_password(
            spp_host,
            spp_username,
            spp_password,
            provider="local",
            verify=spp_verify,
        )
        # Call the token factory directly — this exercises the full
        # SafeguardClient → PasswordAuth → rSTS → Core token exchange
        token = listener._token_factory()

        assert isinstance(token, str)
        assert len(token) > 20  # JWT tokens are much longer than this

    def test_token_factory_can_be_called_multiple_times(self, spp_host, spp_username, spp_password, spp_verify):
        """Each call should produce a fresh token (re-authenticates)."""
        listener = PersistentSafeguardEventListener.from_password(
            spp_host,
            spp_username,
            spp_password,
            provider="local",
            verify=spp_verify,
        )
        token1 = listener._token_factory()
        token2 = listener._token_factory()

        assert isinstance(token1, str)
        assert isinstance(token2, str)
        # Tokens should differ since they're independently issued
        assert token1 != token2

    def test_token_factory_token_works_for_api_calls(self, spp_host, spp_username, spp_password, spp_verify):
        """Token from factory should be usable for authenticated API requests."""
        from pysafeguard import SafeguardClient, Service, TokenAuth

        listener = PersistentSafeguardEventListener.from_password(
            spp_host,
            spp_username,
            spp_password,
            provider="local",
            verify=spp_verify,
        )
        token = listener._token_factory()

        # Use the token with a fresh client
        client = SafeguardClient(spp_host, auth=TokenAuth(token), verify=spp_verify)
        client.login()
        resp = client.get(Service.CORE, "Me")
        assert resp.status_code == 200
