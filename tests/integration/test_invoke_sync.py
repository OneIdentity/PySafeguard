# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Integration tests: sync invoke with various HTTP methods and options."""

import pytest

from pysafeguard import Service

pytestmark = pytest.mark.integration


class TestInvokeGet:
    def test_get_users(self, sync_connection):
        resp = sync_connection.get(Service.CORE, "Users")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_get_with_query_filter(self, sync_connection):
        """Use OData filter to narrow results."""
        resp = sync_connection.get(Service.CORE, "Users", params={"filter": "Disabled eq false"})
        assert resp.status_code == 200

    def test_get_appliance_status(self, sync_connection):
        resp = sync_connection.get(Service.APPLIANCE, "SystemTime")
        assert resp.status_code == 200


class TestInvokePostPutDelete:
    def test_crud_lifecycle(self, sync_connection, unique_name):
        """POST create, GET read, PUT update, DELETE cleanup in one test."""
        user_body = {"PrimaryAuthenticationProvider": {"Id": -1}, "Name": unique_name}

        # CREATE
        create_resp = sync_connection.post(Service.CORE, "Users", json=user_body)
        assert create_resp.status_code == 201
        user_data = create_resp.json()
        user_id = user_data["Id"]

        try:
            # READ
            get_resp = sync_connection.get(Service.CORE, f"Users/{user_id}")
            assert get_resp.status_code == 200
            assert get_resp.json()["Name"] == unique_name

            # UPDATE
            update_body = {**user_data, "Description": "Updated by PySafeguard integration test"}
            put_resp = sync_connection.put(Service.CORE, f"Users/{user_id}", json=update_body)
            assert put_resp.status_code == 200
            assert put_resp.json()["Description"] == "Updated by PySafeguard integration test"
        finally:
            # DELETE (cleanup)
            delete_resp = sync_connection.delete(Service.CORE, f"Users/{user_id}")
            assert delete_resp.status_code in (200, 204)


class TestInvokeWithAdditionalHeaders:
    def test_custom_header_passthrough(self, sync_connection):
        """Additional headers should be sent without breaking the request."""
        resp = sync_connection.get(Service.CORE, "Me", headers={"X-Test": "pytest"})
        assert resp.status_code == 200
