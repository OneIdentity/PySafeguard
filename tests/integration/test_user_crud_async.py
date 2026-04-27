"""Integration tests: async user CRUD lifecycle with full cleanup."""

import pytest

from pysafeguard.data_types import HttpMethods, Services
from tests.integration.conftest import delete_user_async

pytestmark = pytest.mark.integration


@pytest.fixture()
async def async_test_user(async_connection, unique_name):
    """Create a user for testing, yield it, then delete it."""
    user_body = {"PrimaryAuthenticationProvider": {"Id": -1}, "Name": unique_name}
    resp = await async_connection.invoke(HttpMethods.POST, Services.CORE, "Users", body=user_body)
    assert resp.status == 201
    user_data = await resp.json()
    yield user_data
    await delete_user_async(async_connection, user_data["Id"])


class TestAsyncUserRead:
    @pytest.mark.asyncio
    async def test_read_created_user(self, async_connection, async_test_user):
        resp = await async_connection.invoke(HttpMethods.GET, Services.CORE, f"Users/{async_test_user['Id']}")
        assert resp.status == 200
        data = await resp.json()
        assert data["Name"] == async_test_user["Name"]


class TestAsyncUserUpdate:
    @pytest.mark.asyncio
    async def test_update_description(self, async_connection, async_test_user):
        updated = {**async_test_user, "Description": "Async integration test update"}
        resp = await async_connection.invoke(HttpMethods.PUT, Services.CORE, f"Users/{async_test_user['Id']}", body=updated)
        assert resp.status == 200
        data = await resp.json()
        assert data["Description"] == "Async integration test update"


class TestAsyncUserSetPassword:
    @pytest.mark.asyncio
    async def test_set_password(self, async_connection, async_test_user):
        resp = await async_connection.invoke(HttpMethods.PUT, Services.CORE, f"Users/{async_test_user['Id']}/Password", body="TestP@ssw0rd123!")
        assert resp.status in (200, 204)


class TestAsyncUserDelete:
    @pytest.mark.asyncio
    async def test_delete_user(self, async_connection, unique_name):
        user_body = {"PrimaryAuthenticationProvider": {"Id": -1}, "Name": unique_name}
        create_resp = await async_connection.invoke(HttpMethods.POST, Services.CORE, "Users", body=user_body)
        assert create_resp.status == 201
        user_data = await create_resp.json()
        user_id = user_data["Id"]

        delete_resp = await async_connection.invoke(HttpMethods.DELETE, Services.CORE, f"Users/{user_id}")
        assert delete_resp.status in (200, 204)

        get_resp = await async_connection.invoke(HttpMethods.GET, Services.CORE, f"Users/{user_id}")
        assert get_resp.status == 404
