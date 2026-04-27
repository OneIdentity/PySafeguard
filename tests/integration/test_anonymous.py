"""Integration test: anonymous (unauthenticated) access to notification endpoints."""

import pytest

from pysafeguard import HttpMethods, PySafeguardConnection, Services

pytestmark = pytest.mark.integration


class TestAnonymousAccess:
    def test_notification_status(self, spp_host, spp_verify):
        """The Notification/Status endpoint should be accessible without authentication."""
        conn = PySafeguardConnection(spp_host, spp_verify)
        resp = conn.invoke(HttpMethods.GET, Services.NOTIFICATION, "Status")
        assert resp.status_code == 200
        data = resp.json()
        # Status response should have appliance state information
        assert isinstance(data, dict)
