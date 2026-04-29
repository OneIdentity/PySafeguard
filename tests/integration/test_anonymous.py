# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Integration test: anonymous (unauthenticated) access to notification endpoints."""

import pytest

from pysafeguard import SafeguardClient, Service

pytestmark = pytest.mark.integration


class TestAnonymousAccess:
    def test_notification_status(self, spp_host, spp_verify):
        """The Notification/Status endpoint should be accessible without authentication."""
        client = SafeguardClient(spp_host, verify=spp_verify)
        resp = client.get(Service.NOTIFICATION, "Status")
        assert resp.status_code == 200
        data = resp.json()
        # Status response should have appliance state information
        assert isinstance(data, dict)
