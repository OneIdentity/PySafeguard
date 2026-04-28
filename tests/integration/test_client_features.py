"""Integration tests: client features — provider lookup, request(), auto-refresh, error handling."""

from __future__ import annotations

import pytest

from pysafeguard import (
    AsyncSafeguardClient,
    HttpMethod,
    PasswordAuth,
    SafeguardClient,
    Service,
)
from pysafeguard.errors import SafeguardError

pytestmark = pytest.mark.integration


# ===========================================================================
# Provider lookup
# ===========================================================================


class TestSyncProviderLookup:
    def test_get_provider_id_local(self, sync_connection):
        """get_provider_id should resolve 'local' to an rSTS provider ID."""
        provider_id = sync_connection.get_provider_id("local")
        assert isinstance(provider_id, str)
        assert len(provider_id) > 0

    def test_get_provider_id_case_insensitive(self, sync_connection):
        """Provider lookup should be case-insensitive."""
        lower = sync_connection.get_provider_id("local")
        upper = sync_connection.get_provider_id("Local")
        assert lower == upper

    def test_get_provider_id_not_found_raises(self, sync_connection):
        """Looking up a non-existent provider should raise."""
        with pytest.raises(SafeguardError):
            sync_connection.get_provider_id("nonexistent-provider-xyz-12345")


class TestAsyncProviderLookup:
    @pytest.mark.asyncio
    async def test_get_provider_id_local(self, async_connection):
        provider_id = await async_connection.get_provider_id("local")
        assert isinstance(provider_id, str)
        assert len(provider_id) > 0

    @pytest.mark.asyncio
    async def test_get_provider_id_not_found_raises(self, async_connection):
        with pytest.raises(SafeguardError):
            await async_connection.get_provider_id("nonexistent-provider-xyz-12345")


# ===========================================================================
# Low-level request() method
# ===========================================================================


class TestSyncRequest:
    def test_request_get(self, sync_connection):
        """request() should work as a low-level escape hatch."""
        resp = sync_connection.request(HttpMethod.GET, Service.CORE, "Me")
        assert resp.status_code == 200
        me = resp.json()
        assert "Id" in me

    def test_request_with_params(self, sync_connection):
        """request() should pass query params correctly."""
        resp = sync_connection.request(
            HttpMethod.GET,
            Service.CORE,
            "Users",
            params={"filter": "Disabled eq false", "fields": "Id,Name"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_request_post_json(self, sync_connection, unique_name):
        """request() with json= should send JSON body."""
        user_body = {"PrimaryAuthenticationProvider": {"Id": -1}, "Name": unique_name}
        resp = sync_connection.request(HttpMethod.POST, Service.CORE, "Users", json=user_body)
        assert resp.status_code == 201
        user_id = resp.json()["Id"]
        # Cleanup
        sync_connection.delete(Service.CORE, f"Users/{user_id}")


class TestAsyncRequest:
    @pytest.mark.asyncio
    async def test_request_get(self, async_connection):
        resp = await async_connection.request(HttpMethod.GET, Service.CORE, "Me")
        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_request_with_params(self, async_connection):
        resp = await async_connection.request(
            HttpMethod.GET,
            Service.CORE,
            "Users",
            params={"filter": "Disabled eq false"},
        )
        assert resp.status == 200
        data = await resp.json()
        assert isinstance(data, list)


# ===========================================================================
# Error handling — ApiError on 404 / bad requests
# ===========================================================================


class TestSyncErrorHandling:
    def test_404_returns_response(self, sync_connection):
        """A request to a nonexistent resource should return 404 (not raise)."""
        resp = sync_connection.get(Service.CORE, "Users/999999999")
        assert resp.status_code == 404

    def test_bad_method_on_readonly_endpoint(self, sync_connection):
        """DELETE on a read-only endpoint should return an error status."""
        resp = sync_connection.delete(Service.CORE, "Me")
        assert resp.status_code >= 400


class TestAsyncErrorHandling:
    @pytest.mark.asyncio
    async def test_404_returns_response(self, async_connection):
        resp = await async_connection.get(Service.CORE, "Users/999999999")
        assert resp.status == 404


# ===========================================================================
# Auto-refresh behavior
# ===========================================================================


class TestSyncAutoRefresh:
    def test_request_after_logout_and_refresh(self, spp_host, spp_username, spp_password, spp_verify):
        """After logout + refresh, requests should succeed (proves refresh works)."""
        client = SafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        client.login()
        client.logout()
        assert client.user_token is None

        # Refresh re-authenticates
        client.refresh_access_token()
        assert client.user_token is not None

        # API call should work with refreshed token
        resp = client.get(Service.CORE, "Me")
        assert resp.status_code == 200


class TestAsyncAutoRefresh:
    @pytest.mark.asyncio
    async def test_request_after_logout_and_refresh(self, spp_host, spp_username, spp_password, spp_verify):
        client = AsyncSafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        await client.login()
        await client.logout()
        assert client.user_token is None

        await client.refresh_access_token()
        assert client.user_token is not None

        resp = await client.get(Service.CORE, "Me")
        assert resp.status == 200
        await client.close()


# ===========================================================================
# Multiple services
# ===========================================================================


class TestMultipleServices:
    def test_core_and_appliance_services(self, sync_connection):
        """Requests to different services should route correctly."""
        core_resp = sync_connection.get(Service.CORE, "Me")
        assert core_resp.status_code == 200

        appliance_resp = sync_connection.get(Service.APPLIANCE, "SystemTime")
        assert appliance_resp.status_code == 200

    def test_notification_service(self, sync_connection):
        """Notification service should be accessible."""
        resp = sync_connection.get(Service.NOTIFICATION, "Status")
        assert resp.status_code == 200
