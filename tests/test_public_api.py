# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Tests verifying the public API surface of pysafeguard v8.0.

Ensures all expected symbols are exported and deprecated symbols are gone.
"""

from __future__ import annotations

import pysafeguard


class TestPublicExports:
    """Verify __all__ exports are accessible."""

    def test_client_classes(self):
        assert hasattr(pysafeguard, "SafeguardClient")
        assert hasattr(pysafeguard, "AsyncSafeguardClient")

    def test_auth_classes(self):
        assert hasattr(pysafeguard, "PasswordAuth")
        assert hasattr(pysafeguard, "CertificateAuth")
        assert hasattr(pysafeguard, "TokenAuth")
        assert hasattr(pysafeguard, "PkceAuth")

    def test_error_classes(self):
        assert hasattr(pysafeguard, "SafeguardError")
        assert hasattr(pysafeguard, "ApiError")
        assert hasattr(pysafeguard, "AuthenticationError")
        assert hasattr(pysafeguard, "AuthorizationError")
        assert hasattr(pysafeguard, "NotFoundError")
        assert hasattr(pysafeguard, "TransportError")

    def test_enum_classes(self):
        assert hasattr(pysafeguard, "Service")
        assert hasattr(pysafeguard, "HttpMethod")
        assert hasattr(pysafeguard, "A2AType")
        assert hasattr(pysafeguard, "SshKeyFormat")

    def test_a2a_classes(self):
        assert hasattr(pysafeguard, "A2AContext")
        assert hasattr(pysafeguard, "AsyncA2AContext")

    def test_event_classes(self):
        assert hasattr(pysafeguard, "SafeguardEventListener")
        assert hasattr(pysafeguard, "PersistentSafeguardEventListener")
        assert hasattr(pysafeguard, "EventHandlerRegistry")
        assert hasattr(pysafeguard, "EventListenerState")

    def test_hidden_string(self):
        assert hasattr(pysafeguard, "HiddenString")

    def test_all_is_defined(self):
        assert hasattr(pysafeguard, "__all__")
        assert len(pysafeguard.__all__) > 0


class TestRemovedExports:
    """Verify deprecated/removed symbols are no longer accessible."""

    def test_no_pysafeguard_connection(self):
        assert not hasattr(pysafeguard, "PySafeguardConnection")

    def test_no_connection(self):
        assert not hasattr(pysafeguard, "Connection")

    def test_no_async_connection(self):
        assert not hasattr(pysafeguard, "AsyncConnection")

    def test_no_connect_password(self):
        assert not hasattr(pysafeguard, "connect_password")

    def test_no_connect_certificate(self):
        assert not hasattr(pysafeguard, "connect_certificate")

    def test_no_connect_token(self):
        assert not hasattr(pysafeguard, "connect_token")

    def test_no_old_plural_enums_at_top_level(self):
        assert not hasattr(pysafeguard, "Services")
        assert not hasattr(pysafeguard, "HttpMethods")
        assert not hasattr(pysafeguard, "A2ATypes")
        assert not hasattr(pysafeguard, "SshKeyFormats")

    def test_no_safeguard_exception(self):
        assert not hasattr(pysafeguard, "SafeguardException")

    def test_no_web_request_error(self):
        assert not hasattr(pysafeguard, "WebRequestError")
