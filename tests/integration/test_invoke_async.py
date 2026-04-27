"""Integration tests: async invoke() with various HTTP methods."""

import pytest

from pysafeguard.data_types import HttpMethods, Services
from tests.integration.conftest import delete_user_async

pytestmark = pytest.mark.integration


class TestAsyncInvokeGet:
    @pytest.mark.asyncio
    async def test_get_me(self, async_connection):
        resp = await async_connection.invoke(HttpMethods.GET, Services.CORE, "Me")
        assert resp.status == 200
        data = await resp.json()
        assert "Id" in data
        assert "Name" in data

    @pytest.mark.asyncio
    async def test_get_users(self, async_connection):
        resp = await async_connection.invoke(HttpMethods.GET, Services.CORE, "Users")
        assert resp.status == 200
        data = await resp.json()
        assert isinstance(data, list)


class TestAsyncInvokeCrud:
    @pytest.mark.asyncio
    async def test_crud_lifecycle(self, async_connection, unique_name):
        """POST, GET, PUT, DELETE lifecycle via async connection."""
        user_body = {"PrimaryAuthenticationProvider": {"Id": -1}, "Name": unique_name}

        # CREATE
        create_resp = await async_connection.invoke(HttpMethods.POST, Services.CORE, "Users", body=user_body)
        assert create_resp.status == 201
        user_data = await create_resp.json()
        user_id = user_data["Id"]

        try:
            # READ
            get_resp = await async_connection.invoke(HttpMethods.GET, Services.CORE, f"Users/{user_id}")
            assert get_resp.status == 200
            get_data = await get_resp.json()
            assert get_data["Name"] == unique_name

            # UPDATE
            update_body = {**user_data, "Description": "Async integration test"}
            put_resp = await async_connection.invoke(HttpMethods.PUT, Services.CORE, f"Users/{user_id}", body=update_body)
            assert put_resp.status == 200
        finally:
            await delete_user_async(async_connection, user_id)
