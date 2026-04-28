"""Integration test fixtures — shared authenticated connections for live-appliance tests."""

import uuid

import pytest

from pysafeguard import AsyncSafeguardClient, PasswordAuth, SafeguardClient, Service


@pytest.fixture()
def sync_connection(spp_host, spp_username, spp_password, spp_verify):
    """Authenticated sync SafeguardClient (function-scoped)."""
    client = SafeguardClient(
        spp_host,
        auth=PasswordAuth("local", spp_username, spp_password),
        verify=spp_verify,
    )
    client.login()
    return client


@pytest.fixture()
async def async_connection(spp_host, spp_username, spp_password, spp_verify):
    """Authenticated async AsyncSafeguardClient (function-scoped)."""
    client = AsyncSafeguardClient(
        spp_host,
        auth=PasswordAuth("local", spp_username, spp_password),
        verify=spp_verify,
    )
    await client.login()
    return client


@pytest.fixture()
def unique_name():
    """Generate a unique name for test resources to prevent collisions."""
    short_id = uuid.uuid4().hex[:8]
    return f"PyTest_{short_id}"


def delete_user_sync(client, user_id):
    """Best-effort user cleanup — ignores 'not found' errors."""
    try:
        resp = client.delete(Service.CORE, f"Users/{user_id}")
        # 204 No Content = success, 404 = already gone — both are fine
        if resp.status_code not in (200, 204, 404):
            print(f"Warning: cleanup DELETE Users/{user_id} returned {resp.status_code}")
    except Exception as e:
        print(f"Warning: cleanup DELETE Users/{user_id} failed: {e}")


async def delete_user_async(client, user_id):
    """Best-effort async user cleanup."""
    try:
        resp = await client.delete(Service.CORE, f"Users/{user_id}")
        if resp.status not in (200, 204, 404):
            print(f"Warning: async cleanup DELETE Users/{user_id} returned {resp.status}")
    except Exception as e:
        print(f"Warning: async cleanup DELETE Users/{user_id} failed: {e}")
