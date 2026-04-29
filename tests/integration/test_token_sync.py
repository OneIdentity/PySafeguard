# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Integration tests: sync token lifetime and provider lookup."""

import pytest

from pysafeguard import Service

pytestmark = pytest.mark.integration


class TestTokenLifetime:
    def test_get_remaining_token_lifetime(self, sync_connection):
        remaining = sync_connection.token_lifetime_remaining
        assert remaining is not None
        assert isinstance(remaining, int)
        assert remaining > 0


class TestProviderLookup:
    def test_get_provider_id_local(self, sync_connection):
        """The 'Local' provider should always exist on a Safeguard appliance."""
        provider_id = sync_connection.get_provider_id("Local")
        assert provider_id is not None
        assert len(provider_id) > 0

    def test_get_provider_id_case_insensitive(self, sync_connection):
        """Provider lookup is case-insensitive."""
        upper = sync_connection.get_provider_id("LOCAL")
        lower = sync_connection.get_provider_id("local")
        assert upper == lower

    def test_get_provider_id_not_found(self, sync_connection):
        with pytest.raises(Exception, match="Unable to find Provider"):
            sync_connection.get_provider_id("NonexistentProvider_XYZ_999")


class TestAuthenticationProviders:
    def test_list_providers(self, sync_connection):
        resp = sync_connection.get(Service.CORE, "AuthenticationProviders")
        assert resp.status_code == 200
        providers = resp.json()
        assert isinstance(providers, list)
        assert len(providers) > 0
        # Each provider should have Name and RstsProviderId
        for p in providers:
            assert "Name" in p
            assert "RstsProviderId" in p
