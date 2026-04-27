"""Integration test fixtures — shared authenticated connections for live-appliance tests."""

import uuid

import pytest

from pysafeguard import HttpMethods, PySafeguardConnection, Services
from pysafeguard.async_connection import AsyncConnection


@pytest.fixture()
def sync_connection(spp_host, spp_username, spp_password, spp_verify):
    """Authenticated sync PySafeguardConnection (function-scoped)."""
    conn = PySafeguardConnection(spp_host, spp_verify)
    conn.connect_password(spp_username, spp_password)
    return conn


@pytest.fixture()
async def async_connection(spp_host, spp_username, spp_password, spp_verify):
    """Authenticated async AsyncConnection (function-scoped)."""
    conn = AsyncConnection(spp_host, spp_verify)
    await conn.connect_password(spp_username, spp_password)
    return conn


@pytest.fixture()
def unique_name():
    """Generate a unique name for test resources to prevent collisions."""
    short_id = uuid.uuid4().hex[:8]
    return f"PyTest_{short_id}"


def delete_user_sync(conn, user_id):
    """Best-effort user cleanup — ignores 'not found' errors."""
    try:
        resp = conn.invoke(HttpMethods.DELETE, Services.CORE, f"Users/{user_id}")
        # 204 No Content = success, 404 = already gone — both are fine
        if resp.status_code not in (200, 204, 404):
            print(f"Warning: cleanup DELETE Users/{user_id} returned {resp.status_code}")
    except Exception as e:
        print(f"Warning: cleanup DELETE Users/{user_id} failed: {e}")


async def delete_user_async(conn, user_id):
    """Best-effort async user cleanup."""
    try:
        resp = await conn.invoke(HttpMethods.DELETE, Services.CORE, f"Users/{user_id}")
        if resp.status not in (200, 204, 404):
            print(f"Warning: async cleanup DELETE Users/{user_id} returned {resp.status}")
    except Exception as e:
        print(f"Warning: async cleanup DELETE Users/{user_id} failed: {e}")
