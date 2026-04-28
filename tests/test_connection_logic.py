"""Unit tests for Connection logic using mocked HTTP responses.

These test request construction, auth flows, body handling, and error paths
without requiring a live appliance.

The sync Connection uses a persistent ``requests.Session`` internally, so all
mocks patch ``Session.request`` (the instance method) rather than a module-level
``request`` function.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from requests import Session

from pysafeguard.connection import Connection, WebRequestError
from pysafeguard.data_types import HttpMethods, Services


_HTTP_REASONS = {200: "OK", 201: "Created", 204: "No Content", 400: "Bad Request", 404: "Not Found", 500: "Internal Server Error"}


def _make_response(status_code=200, json_data=None, headers=None, content_type="application/json; charset=utf-8", text=""):
    """Build a fake requests.Response-like object.

    Default content-type matches the real Safeguard appliance which always
    returns ``application/json; charset=utf-8``.
    """
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"content-type": content_type, **(headers or {})}
    resp.json.return_value = json_data
    resp.text = text or json.dumps(json_data) if json_data else text
    resp.reason = _HTTP_REASONS.get(status_code, "Unknown")
    resp.url = "https://host/fake"
    resp.request = SimpleNamespace(method="GET")
    return resp


class TestInvokeUrlConstruction:
    """Verify invoke() builds the correct URL for various service/endpoint combos."""

    @patch.object(Session, "request", return_value=_make_response())
    def test_core_endpoint(self, mock_request):
        conn = Connection("myhost.example.com")
        conn.connect_token("tok")
        conn.invoke(HttpMethods.GET, Services.CORE, "Users")
        url = mock_request.call_args[0][1]
        assert "service/core/v4/Users" in url

    @patch.object(Session, "request", return_value=_make_response())
    def test_rsts_no_api_version(self, mock_request):
        """RSTS service should NOT include the API version in the path."""
        conn = Connection("host")
        conn.invoke(HttpMethods.POST, Services.RSTS, "oauth2/token")
        url = mock_request.call_args[0][1]
        assert "v4" not in url
        assert "RSTS" in url
        assert "oauth2/token" in url

    @patch.object(Session, "request", return_value=_make_response())
    def test_host_override(self, mock_request):
        """invoke(host=...) should override the connection's default host."""
        conn = Connection("default-host")
        conn.invoke(HttpMethods.GET, Services.CORE, "Me", host="override-host")
        url = mock_request.call_args[0][1]
        assert "override-host" in url
        assert "default-host" not in url

    @patch.object(Session, "request", return_value=_make_response())
    def test_query_params(self, mock_request):
        conn = Connection("host")
        conn.invoke(HttpMethods.GET, Services.CORE, "Users", query={"filter": "Name eq 'test'"})
        url = mock_request.call_args[0][1]
        assert "filter=" in url

    @patch.object(Session, "request", return_value=_make_response())
    def test_custom_api_version_override(self, mock_request):
        conn = Connection("host", apiVersion="v4")
        conn.invoke(HttpMethods.GET, Services.CORE, "Me", apiVersion="v3")
        url = mock_request.call_args[0][1]
        assert "v3" in url
        assert "v4" not in url


class TestInvokeBodyHandling:
    """Verify JSON vs string body handling in _execute_web_request."""

    @patch.object(Session, "request", return_value=_make_response())
    def test_post_dict_body_sent_as_json(self, mock_request):
        conn = Connection("host")
        conn.invoke(HttpMethods.POST, Services.CORE, "Users", body={"Name": "Test"})
        _, kwargs = mock_request.call_args
        assert kwargs["json"] == {"Name": "Test"}
        assert kwargs["data"] is None

    @patch.object(Session, "request", return_value=_make_response())
    def test_post_string_body_sent_as_data(self, mock_request):
        conn = Connection("host")
        conn.headers["content-type"] = "text/plain"
        conn.invoke(HttpMethods.POST, Services.CORE, "Endpoint", body="raw string")
        _, kwargs = mock_request.call_args
        assert kwargs["data"] == "raw string"
        assert kwargs["json"] is None

    @patch.object(Session, "request", return_value=_make_response())
    def test_get_with_body_none(self, mock_request):
        conn = Connection("host")
        conn.invoke(HttpMethods.GET, Services.CORE, "Me")
        _, kwargs = mock_request.call_args
        assert kwargs["data"] is None
        assert kwargs["json"] is None

    def test_post_non_string_body_with_content_type_raises(self):
        """When content-type is already set and body is not a string, raise TypeError."""
        conn = Connection("host")
        conn.headers["content-type"] = "text/plain"
        with pytest.raises(TypeError, match="expected: body as a string"):
            conn.invoke(HttpMethods.POST, Services.CORE, "Endpoint", body={"dict": "value"})


class TestInvokeHeaders:
    @patch.object(Session, "request", return_value=_make_response())
    def test_additional_headers_merged(self, mock_request):
        conn = Connection("host")
        conn.connect_token("tok")
        conn.invoke(HttpMethods.GET, Services.CORE, "Me", additionalHeaders={"X-Custom": "value"})
        _, kwargs = mock_request.call_args
        headers = kwargs["headers"]
        assert headers["X-Custom"] == "value"
        assert "Bearer tok" in headers["authorization"]

    @patch.object(Session, "request", return_value=_make_response())
    def test_explicit_content_type_preserved(self, mock_request):
        """When content-type is explicitly provided, don't override it."""
        conn = Connection("host")
        conn.invoke(HttpMethods.POST, Services.CORE, "Endpoint", body="xml data", additionalHeaders={"content-type": "application/xml"})
        _, kwargs = mock_request.call_args
        assert kwargs["data"] == "xml data"


class TestConnectPassword:
    def test_successful_auth_sets_token(self):
        """Simulate the two-step auth: RSTS → LoginResponse."""
        rsts_response = _make_response(
            200,
            {
                "access_token": "rsts-token",
                "expires_in": 299,
                "scope": "rsts:sts:primaryproviderid:local:pwd",
                "success": True,
                "token_type": "Bearer",
            },
        )
        login_response = _make_response(
            200,
            {
                "Status": "Success",
                "UserToken": "user-token-123",
                "PrimaryProviderId": None,
                "SecondaryProviderId": None,
                "WebClientInactivityTimeout": 15,
                "DesktopClientInactivityTimeout": 1440,
            },
        )
        with patch.object(Session, "request", side_effect=[rsts_response, login_response]):
            conn = Connection("host", verify=False)
            conn.connect_password("admin", "pass")

        assert conn.UserToken == "user-token-123"
        assert "Bearer user-token-123" in conn.headers["authorization"]

    def test_rsts_failure_raises(self):
        error_resp = _make_response(
            400,
            json_data={"error": "invalid_request", "error_description": "Access denied.", "success": False},
            text='{"error":"invalid_request","error_description":"Access denied.","success":false}',
        )
        with patch.object(Session, "request", return_value=error_resp):
            conn = Connection("host", verify=False)
            with pytest.raises(WebRequestError):
                conn.connect_password("admin", "wrong")

    def test_login_response_failure_raises(self):
        """RSTS succeeds but LoginResponse fails."""
        rsts_ok = _make_response(
            200,
            {
                "access_token": "rsts-token",
                "expires_in": 299,
                "scope": "rsts:sts:primaryproviderid:local:pwd",
                "success": True,
                "token_type": "Bearer",
            },
        )
        login_fail = _make_response(
            400,
            json_data={"Code": 60519, "Message": "Invalid STS access_token."},
            text='{"Code":60519,"Message":"Invalid STS access_token."}',
        )
        with patch.object(Session, "request", side_effect=[rsts_ok, login_fail]):
            conn = Connection("host", verify=False)
            with pytest.raises(WebRequestError):
                conn.connect_password("admin", "pass")


class TestGetProviderIdMocked:
    def test_finds_provider_case_insensitive(self):
        providers = [
            {
                "Id": -1,
                "Name": "Local",
                "TypeReferenceName": "Local",
                "IdentityProviderId": -1,
                "RstsProviderId": "local",
                "RstsProviderScope": "rsts:sts:primaryproviderid:local",
                "ForceAsDefault": False,
            },
            {
                "Id": -2,
                "Name": "Certificate",
                "TypeReferenceName": "Certificate",
                "IdentityProviderId": -2,
                "RstsProviderId": "certificate",
                "RstsProviderScope": "rsts:sts:primaryproviderid:certificate",
                "ForceAsDefault": False,
            },
        ]
        with patch.object(Session, "request", return_value=_make_response(200, providers)):
            conn = Connection("host", verify=False)
            conn.connect_token("tok")
            result = conn.get_provider_id("local")
            assert result == "local"

    def test_provider_not_found_raises(self):
        providers = [
            {
                "Id": -1,
                "Name": "Local",
                "TypeReferenceName": "Local",
                "IdentityProviderId": -1,
                "RstsProviderId": "local",
                "RstsProviderScope": "rsts:sts:primaryproviderid:local",
                "ForceAsDefault": False,
            },
        ]
        with patch.object(Session, "request", return_value=_make_response(200, providers)):
            conn = Connection("host", verify=False)
            conn.connect_token("tok")
            with pytest.raises(Exception, match="Unable to find Provider"):
                conn.get_provider_id("nonexistent")


class TestGetRemainingTokenLifetimeMocked:
    def test_returns_minutes(self):
        resp = _make_response(
            200,
            json_data={"CurrentTime": "2026-04-27T22:19:54.6815898Z"},
            headers={"x-tokenlifetimeremaining": "1440"},
        )
        with patch.object(Session, "request", return_value=resp):
            conn = Connection("host", verify=False)
            conn.connect_token("tok")
            assert conn.get_remaining_token_lifetime() == 1440

    def test_returns_none_when_header_missing(self):
        resp = _make_response(
            200,
            json_data={"CurrentTime": "2026-04-27T22:19:54.6815898Z"},
            headers={},
        )
        with patch.object(Session, "request", return_value=resp):
            conn = Connection("host", verify=False)
            conn.connect_token("tok")
            assert conn.get_remaining_token_lifetime() is None


class TestA2AValidation:
    def test_empty_api_key_raises(self):
        with pytest.raises(Exception, match="apiKey may not be null or empty"):
            Connection.a2a_get_credential("host", "", "cert.pem", "key.pem")

    def test_empty_cert_and_key_raises(self):
        with pytest.raises(Exception, match="cert path and key path may not be null or empty"):
            Connection.a2a_get_credential("host", "my-key", "", "")
