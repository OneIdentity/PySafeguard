# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Verify that removed v7.x factory functions are no longer importable.

In v8.0, the module-level factory functions (connect_password, connect_certificate,
connect_token) were removed in favor of SafeguardClient/AsyncSafeguardClient
with explicit auth objects.

These tests serve as regression guards to prevent accidental re-introduction.
"""

import pytest

pytestmark = pytest.mark.integration


class TestRemovedFactories:
    """Verify v7.x factory functions are no longer available."""

    def test_connect_password_not_importable(self):
        with pytest.raises(ImportError):
            from pysafeguard import connect_password  # noqa: F401

    def test_connect_certificate_not_importable(self):
        with pytest.raises(ImportError):
            from pysafeguard import connect_certificate  # noqa: F401

    def test_connect_token_not_importable(self):
        with pytest.raises(ImportError):
            from pysafeguard import connect_token  # noqa: F401

    def test_pysafeguardconnection_not_importable(self):
        with pytest.raises(ImportError):
            from pysafeguard import PySafeguardConnection  # noqa: F401

    def test_connection_not_importable(self):
        with pytest.raises(ImportError):
            from pysafeguard import Connection  # noqa: F401

    def test_safeguard_exception_not_importable(self):
        """Old exception name should be gone — use SafeguardError instead."""
        with pytest.raises(ImportError):
            from pysafeguard import SafeguardException  # noqa: F401
