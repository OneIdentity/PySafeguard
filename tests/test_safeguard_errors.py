# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Tests for the new v8.0 error hierarchy (pysafeguard.errors).

Covers SafeguardError, ApiError, status-code mapping, from_response factory,
and structured JSON parsing.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock


from pysafeguard.errors import (
    ApiError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    SafeguardError,
    TransportError,
)


# ---------------------------------------------------------------------------
# SafeguardError
# ---------------------------------------------------------------------------


class TestSafeguardError:
    def test_plain_message(self):
        err = SafeguardError("something went wrong")
        assert str(err) == "something went wrong"
        assert err.status_code is None
        assert err.error_code is None
        assert err.error_message is None
        assert err.response_body is None

    def test_inherits_exception(self):
        assert isinstance(SafeguardError(), Exception)

    def test_has_response_false(self):
        assert not SafeguardError("err").has_response

    def test_has_response_true(self):
        assert SafeguardError("err", response_body="{}").has_response

    def test_parses_code_and_message(self):
        body = '{"Code": 60519, "Message": "Invalid STS access_token."}'
        err = SafeguardError("err", status_code=400, response_body=body)
        assert err.error_code == 60519
        assert err.error_message == "Invalid STS access_token."
        assert err.status_code == 400

    def test_parses_oauth_error_field(self):
        body = '{"error": "invalid_request", "error_description": "Access denied."}'
        err = SafeguardError("err", response_body=body)
        assert err.error_message == "invalid_request"

    def test_non_json_no_crash(self):
        err = SafeguardError("err", response_body="<html>not json</html>")
        assert err.error_code is None
        assert err.response_body == "<html>not json</html>"

    def test_display_falls_back_to_error_message(self):
        body = '{"Code": 1, "Message": "Token expired."}'
        err = SafeguardError("", response_body=body)
        assert str(err) == "Token expired."


# ---------------------------------------------------------------------------
# ApiError.from_response
# ---------------------------------------------------------------------------


class TestApiErrorFromResponse:
    def _make_response(self, status_code=400, reason="Bad Request", method="POST", url="https://host/endpoint", text=""):
        resp = MagicMock()
        resp.status_code = status_code
        resp.reason = reason
        resp.url = url
        resp.text = text
        resp.request = SimpleNamespace(method=method)
        return resp

    def test_basic_api_error(self):
        resp = self._make_response(500, "Internal Server Error")
        err = ApiError.from_response(resp)
        assert isinstance(err, ApiError)
        assert err.status_code == 500
        assert "500" in str(err)

    def test_401_returns_authentication_error(self):
        resp = self._make_response(401, "Unauthorized")
        err = ApiError.from_response(resp)
        assert isinstance(err, AuthenticationError)
        assert isinstance(err, ApiError)

    def test_403_returns_authorization_error(self):
        resp = self._make_response(403, "Forbidden")
        err = ApiError.from_response(resp)
        assert isinstance(err, AuthorizationError)

    def test_404_returns_not_found_error(self):
        resp = self._make_response(404, "Not Found")
        err = ApiError.from_response(resp)
        assert isinstance(err, NotFoundError)

    def test_includes_response_body(self):
        resp = self._make_response(400, text='{"Code": 123, "Message": "Bad input"}')
        err = ApiError.from_response(resp)
        assert err.response_body == '{"Code": 123, "Message": "Bad input"}'
        assert err.error_code == 123

    def test_includes_url_in_message(self):
        resp = self._make_response(400, url="https://host/service/core/v4/Users")
        err = ApiError.from_response(resp)
        assert "Users" in str(err)


# ---------------------------------------------------------------------------
# Hierarchy
# ---------------------------------------------------------------------------


class TestErrorHierarchy:
    def test_authentication_is_api_error(self):
        assert issubclass(AuthenticationError, ApiError)
        assert issubclass(AuthenticationError, SafeguardError)

    def test_authorization_is_api_error(self):
        assert issubclass(AuthorizationError, ApiError)

    def test_not_found_is_api_error(self):
        assert issubclass(NotFoundError, ApiError)

    def test_transport_is_safeguard_error_not_api_error(self):
        assert issubclass(TransportError, SafeguardError)
        assert not issubclass(TransportError, ApiError)

    def test_catch_all_safeguard_error(self):
        """All error types should be catchable via SafeguardError."""
        for cls in (ApiError, AuthenticationError, AuthorizationError, NotFoundError, TransportError):
            err = cls("test")
            assert isinstance(err, SafeguardError)
