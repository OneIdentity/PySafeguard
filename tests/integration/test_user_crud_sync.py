"""Integration tests: sync user CRUD lifecycle with full cleanup."""

import pytest

from pysafeguard import Service
from tests.integration.conftest import delete_user_sync

pytestmark = pytest.mark.integration


@pytest.fixture()
def test_user(sync_connection, unique_name):
    """Create a user for testing, yield it, then delete it."""
    user_body = {"PrimaryAuthenticationProvider": {"Id": -1}, "Name": unique_name}
    resp = sync_connection.post(Service.CORE, "Users", json=user_body)
    assert resp.status_code == 201
    user_data = resp.json()
    yield user_data
    delete_user_sync(sync_connection, user_data["Id"])


class TestUserRead:
    def test_read_created_user(self, sync_connection, test_user):
        resp = sync_connection.get(Service.CORE, f"Users/{test_user['Id']}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["Name"] == test_user["Name"]
        assert data["Id"] == test_user["Id"]


class TestUserUpdate:
    def test_update_description(self, sync_connection, test_user):
        updated = {**test_user, "Description": "Integration test update"}
        resp = sync_connection.put(Service.CORE, f"Users/{test_user['Id']}", json=updated)
        assert resp.status_code == 200
        assert resp.json()["Description"] == "Integration test update"


class TestUserSetPassword:
    def test_set_password(self, sync_connection, test_user):
        resp = sync_connection.put(Service.CORE, f"Users/{test_user['Id']}/Password", json="TestP@ssw0rd123!")
        assert resp.status_code in (200, 204)


class TestUserDelete:
    def test_delete_user(self, sync_connection, unique_name):
        """Create and immediately delete a user — verify the DELETE itself."""
        user_body = {"PrimaryAuthenticationProvider": {"Id": -1}, "Name": unique_name}
        create_resp = sync_connection.post(Service.CORE, "Users", json=user_body)
        assert create_resp.status_code == 201
        user_id = create_resp.json()["Id"]

        delete_resp = sync_connection.delete(Service.CORE, f"Users/{user_id}")
        assert delete_resp.status_code in (200, 204)

        # Confirm deleted — should be 404
        get_resp = sync_connection.get(Service.CORE, f"Users/{user_id}")
        assert get_resp.status_code == 404
