# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Tests for SafeguardClient request logic using mocked HTTP responses.

Tests URL construction, header merging, body handling, verb methods,
and error paths using the new v8.0 API surface.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from requests import Session

from pysafeguard.auth import TokenAuth
from pysafeguard.client import SafeguardClient
from pysafeguard.data_types import HttpMethod, Service
from pysafeguard.errors import SafeguardError


_HTTP_REASONS = {200: "OK", 400: "Bad Request", 404: "Not Found", 500: "Internal Server Error"}


def _make_response(status_code=200, json_data=None, headers=None, content_type="application/json; charset=utf-8", text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"content-type": content_type, **(headers or {})}
    resp.json.return_value = json_data
    resp.text = text or json.dumps(json_data) if json_data else text
    resp.reason = _HTTP_REASONS.get(status_code, "Unknown")
    resp.url = "https://host/fake"
    resp.request = SimpleNamespace(method="GET")
    return resp


# ---------------------------------------------------------------------------
# URL construction
# ---------------------------------------------------------------------------


class TestRequestUrlConstruction:
    @patch.object(Session, "request", return_value=_make_response())
    def test_core_endpoint(self, mock_req):
        client = SafeguardClient("myhost.example.com", auth=TokenAuth("tok"))
        client.login()
        client.get(Service.CORE, "Users")
        url = mock_req.call_args[0][1]
        assert "service/core/v4/Users" in url

    @patch.object(Session, "request", return_value=_make_response())
    def test_rsts_no_api_version(self, mock_req):
        client = SafeguardClient("host")
        client.request(HttpMethod.POST, Service.RSTS, "oauth2/token")
        url = mock_req.call_args[0][1]
        assert "v4" not in url
        assert "RSTS" in url
        assert "oauth2/token" in url

    @patch.object(Session, "request", return_value=_make_response())
    def test_host_override(self, mock_req):
        client = SafeguardClient("default-host")
        client.get(Service.CORE, "Me", host="override-host")
        url = mock_req.call_args[0][1]
        assert "override-host" in url
        assert "default-host" not in url

    @patch.object(Session, "request", return_value=_make_response())
    def test_query_params(self, mock_req):
        client = SafeguardClient("host")
        client.get(Service.CORE, "Users", params={"filter": "Name eq 'test'"})
        url = mock_req.call_args[0][1]
        assert "filter=" in url

    @patch.object(Session, "request", return_value=_make_response())
    def test_custom_api_version_override(self, mock_req):
        client = SafeguardClient("host", api_version="v4")
        client.get(Service.CORE, "Me", api_version="v3")
        url = mock_req.call_args[0][1]
        assert "v3" in url
        assert "v4" not in url


# ---------------------------------------------------------------------------
# Body handling
# ---------------------------------------------------------------------------


class TestRequestBodyHandling:
    @patch.object(Session, "request", return_value=_make_response())
    def test_post_json_body(self, mock_req):
        client = SafeguardClient("host")
        client.post(Service.CORE, "Users", json={"Name": "Test"})
        _, kwargs = mock_req.call_args
        assert kwargs["json"] == {"Name": "Test"}
        assert kwargs["data"] is None

    @patch.object(Session, "request", return_value=_make_response())
    def test_post_data_body(self, mock_req):
        client = SafeguardClient("host")
        client.post(Service.CORE, "Endpoint", data="raw string")
        _, kwargs = mock_req.call_args
        assert kwargs["data"] == "raw string"
        assert kwargs["json"] is None

    @patch.object(Session, "request", return_value=_make_response())
    def test_get_with_no_body(self, mock_req):
        client = SafeguardClient("host")
        client.get(Service.CORE, "Me")
        _, kwargs = mock_req.call_args
        assert kwargs["data"] is None
        assert kwargs["json"] is None


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------


class TestRequestHeaders:
    @patch.object(Session, "request", return_value=_make_response())
    def test_additional_headers_merged(self, mock_req):
        client = SafeguardClient("host", auth=TokenAuth("tok"))
        client.login()
        client.get(Service.CORE, "Me", headers={"X-Custom": "value"})
        _, kwargs = mock_req.call_args
        headers = kwargs["headers"]
        assert headers["X-Custom"] == "value"
        assert "Bearer tok" in headers["authorization"]

    @patch.object(Session, "request", return_value=_make_response())
    def test_default_accept_header(self, mock_req):
        client = SafeguardClient("host")
        client.get(Service.CORE, "Me")
        _, kwargs = mock_req.call_args
        assert kwargs["headers"]["accept"] == "application/json"


# ---------------------------------------------------------------------------
# HTTP verb methods
# ---------------------------------------------------------------------------


class TestVerbMethods:
    @patch.object(Session, "request", return_value=_make_response())
    def test_get(self, mock_req):
        client = SafeguardClient("host")
        client.get(Service.CORE, "Users")
        assert mock_req.call_args[0][0] == "GET"

    @patch.object(Session, "request", return_value=_make_response())
    def test_post(self, mock_req):
        client = SafeguardClient("host")
        client.post(Service.CORE, "Users", json={"Name": "Test"})
        assert mock_req.call_args[0][0] == "POST"

    @patch.object(Session, "request", return_value=_make_response())
    def test_put(self, mock_req):
        client = SafeguardClient("host")
        client.put(Service.CORE, "Users/1", json={"Name": "Updated"})
        assert mock_req.call_args[0][0] == "PUT"

    @patch.object(Session, "request", return_value=_make_response())
    def test_delete(self, mock_req):
        client = SafeguardClient("host")
        client.delete(Service.CORE, "Users/1")
        assert mock_req.call_args[0][0] == "DELETE"


# ---------------------------------------------------------------------------
# Provider lookup (mocked)
# ---------------------------------------------------------------------------


class TestGetProviderIdMocked:
    def test_finds_provider_case_insensitive(self):
        providers = [
            {"Id": -1, "Name": "Local", "RstsProviderId": "local"},
            {"Id": -2, "Name": "Certificate", "RstsProviderId": "certificate"},
        ]
        with patch.object(Session, "request", return_value=_make_response(200, providers)):
            client = SafeguardClient("host", auth=TokenAuth("tok"))
            client.login()
            result = client.get_provider_id("local")
            assert result == "local"

    def test_provider_not_found_raises(self):
        providers = [{"Id": -1, "Name": "Local", "RstsProviderId": "local"}]
        with patch.object(Session, "request", return_value=_make_response(200, providers)):
            client = SafeguardClient("host", auth=TokenAuth("tok"))
            client.login()
            with pytest.raises(SafeguardError, match="Unable to find Provider"):
                client.get_provider_id("nonexistent")


# ---------------------------------------------------------------------------
# Token lifetime
# ---------------------------------------------------------------------------


class TestTokenLifetimeRemaining:
    def test_returns_minutes(self):
        resp = _make_response(200, json_data={"CurrentTime": "2026-04-27T22:19:54Z"}, headers={"x-tokenlifetimeremaining": "1440"})
        with patch.object(Session, "request", return_value=resp):
            client = SafeguardClient("host", auth=TokenAuth("tok"))
            client.login()
            assert client.token_lifetime_remaining == 1440

    def test_returns_none_when_header_missing(self):
        resp = _make_response(200, json_data={"CurrentTime": "2026-04-27T22:19:54Z"}, headers={})
        with patch.object(Session, "request", return_value=resp):
            client = SafeguardClient("host", auth=TokenAuth("tok"))
            client.login()
            assert client.token_lifetime_remaining is None


# ---------------------------------------------------------------------------
# Event listener factories
# ---------------------------------------------------------------------------


class TestEventListenerFactories:
    def test_get_event_listener_without_token_raises(self):
        client = SafeguardClient("host")
        with pytest.raises(SafeguardError, match="no user token"):
            client.get_event_listener()

    def test_get_persistent_event_listener_without_auth_raises(self):
        client = SafeguardClient("host")
        with pytest.raises(SafeguardError, match="No auth strategy"):
            client.get_persistent_event_listener()
