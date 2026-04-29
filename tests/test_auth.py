# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Tests for auth strategy objects (pysafeguard.auth).

Covers construction, protocol conformance, secret wrapping, can_refresh,
and the sync authenticate/refresh flow for PasswordAuth using mocked HTTP.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from requests import Session

from pysafeguard.auth import Auth, CertificateAuth, PasswordAuth, PkceAuth, TokenAuth
from pysafeguard.errors import ApiError, SafeguardError
from pysafeguard.hidden_string import HiddenString


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestAuthProtocol:
    def test_password_auth_is_auth(self):
        assert isinstance(PasswordAuth("local", "admin", "pass"), Auth)

    def test_certificate_auth_is_auth(self):
        assert isinstance(CertificateAuth("cert.pem", "key.pem"), Auth)

    def test_pkce_auth_is_auth(self):
        assert isinstance(PkceAuth("local", "admin", "pass"), Auth)

    def test_token_auth_is_auth(self):
        assert isinstance(TokenAuth("tok"), Auth)


# ---------------------------------------------------------------------------
# PasswordAuth
# ---------------------------------------------------------------------------


class TestPasswordAuth:
    def test_construction(self):
        auth = PasswordAuth("local", "admin", "secret")
        assert auth.provider == "local"
        assert auth.username == "admin"
        assert isinstance(auth.password, HiddenString)
        assert auth.password.get_value() == "secret"

    def test_hidden_string_passthrough(self):
        hs = HiddenString("pass")
        auth = PasswordAuth("local", "admin", hs)
        assert auth.password is hs

    def test_can_refresh(self):
        assert PasswordAuth("local", "admin", "pass").can_refresh is True

    def test_frozen(self):
        auth = PasswordAuth("local", "admin", "pass")
        with pytest.raises(AttributeError):
            auth.provider = "other"  # type: ignore[misc]

    def test_repr_hides_password(self):
        auth = PasswordAuth("local", "admin", "super-secret")
        r = repr(auth)
        assert "super-secret" not in r
        assert "local" in r
        assert "admin" in r

    def test_dispose_clears_password(self):
        auth = PasswordAuth("local", "admin", "secret")
        auth.dispose()
        with pytest.raises(RuntimeError, match="disposed"):
            auth.password.get_value()


class TestPasswordAuthFlow:
    """Test the full PasswordAuth.authenticate() flow with mocked HTTP."""

    def _make_response(self, status_code=200, json_data=None, content_type="application/json; charset=utf-8"):
        resp = MagicMock()
        resp.status_code = status_code
        resp.headers = {"content-type": content_type}
        resp.json.return_value = json_data
        resp.text = json.dumps(json_data) if json_data else ""
        resp.reason = "OK" if status_code == 200 else "Bad Request"
        resp.url = "https://host/fake"
        resp.request = SimpleNamespace(method="POST")
        return resp

    def test_successful_auth(self):
        from pysafeguard.client import SafeguardClient

        rsts_resp = self._make_response(
            200,
            {
                "access_token": "rsts-tok",
                "expires_in": 299,
                "token_type": "Bearer",
            },
        )
        login_resp = self._make_response(
            200,
            {
                "Status": "Success",
                "UserToken": "user-tok-123",
            },
        )

        with (
            patch("pysafeguard.auth._resolve_provider", return_value="local"),
            patch.object(Session, "request", side_effect=[rsts_resp, login_resp]),
        ):
            client = SafeguardClient("host", verify=False)
            auth = PasswordAuth("local", "admin", "pass")
            token = auth.authenticate(client)

        assert token == "user-tok-123"

    def test_rsts_failure_raises(self):
        from pysafeguard.client import SafeguardClient

        error_resp = self._make_response(400, {"error": "invalid_request"})
        with (
            patch("pysafeguard.auth._resolve_provider", return_value="local"),
            patch.object(Session, "request", return_value=error_resp),
        ):
            client = SafeguardClient("host", verify=False)
            auth = PasswordAuth("local", "admin", "wrong")
            with pytest.raises(ApiError):
                auth.authenticate(client)

    def test_login_response_failure_raises(self):
        from pysafeguard.client import SafeguardClient

        rsts_ok = self._make_response(200, {"access_token": "tok"})
        login_fail = self._make_response(400, {"Code": 60519, "Message": "Invalid STS access_token."})

        with (
            patch("pysafeguard.auth._resolve_provider", return_value="local"),
            patch.object(Session, "request", side_effect=[rsts_ok, login_fail]),
        ):
            client = SafeguardClient("host", verify=False)
            auth = PasswordAuth("local", "admin", "pass")
            with pytest.raises(ApiError):
                auth.authenticate(client)


# ---------------------------------------------------------------------------
# CertificateAuth
# ---------------------------------------------------------------------------


class TestCertificateAuth:
    def test_construction(self):
        auth = CertificateAuth("cert.pem", "key.pem")
        assert auth.cert_file == "cert.pem"
        assert auth.key_file == "key.pem"
        assert auth.provider == "certificate"

    def test_custom_provider(self):
        auth = CertificateAuth("c.pem", "k.pem", provider="my-provider")
        assert auth.provider == "my-provider"

    def test_can_refresh(self):
        assert CertificateAuth("c.pem", "k.pem").can_refresh is True

    def test_cert_tuple(self):
        auth = CertificateAuth("c.pem", "k.pem")
        assert auth.cert_tuple == ("c.pem", "k.pem")


# ---------------------------------------------------------------------------
# PkceAuth
# ---------------------------------------------------------------------------


class TestPkceAuth:
    def test_construction(self):
        auth = PkceAuth("local", "admin", "pass")
        assert auth.provider == "local"
        assert auth.username == "admin"
        assert isinstance(auth.password, HiddenString)
        assert auth.secondary_password is None

    def test_secondary_password(self):
        auth = PkceAuth("local", "admin", "pass", "mfa-code")
        assert auth.secondary_password is not None
        assert auth.secondary_password.get_value() == "mfa-code"

    def test_can_refresh_without_mfa(self):
        assert PkceAuth("local", "admin", "pass").can_refresh is True

    def test_cannot_refresh_with_mfa(self):
        assert PkceAuth("local", "admin", "pass", "mfa").can_refresh is False

    def test_repr_hides_secrets(self):
        auth = PkceAuth("local", "admin", "pass", "mfa")
        r = repr(auth)
        assert "pass" not in r
        assert "mfa" not in r

    def test_dispose(self):
        auth = PkceAuth("local", "admin", "pass", "mfa")
        auth.dispose()
        with pytest.raises(RuntimeError, match="disposed"):
            auth.password.get_value()
        with pytest.raises(RuntimeError, match="disposed"):
            auth.secondary_password.get_value()  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# TokenAuth
# ---------------------------------------------------------------------------


class TestTokenAuth:
    def test_construction(self):
        auth = TokenAuth("my-token")
        assert isinstance(auth.token, HiddenString)
        assert auth.token.get_value() == "my-token"

    def test_can_refresh(self):
        assert TokenAuth("tok").can_refresh is False

    def test_authenticate_returns_token(self):
        from pysafeguard.client import SafeguardClient

        client = SafeguardClient("host")
        auth = TokenAuth("my-token")
        assert auth.authenticate(client) == "my-token"

    def test_refresh_raises(self):
        from pysafeguard.client import SafeguardClient

        client = SafeguardClient("host")
        auth = TokenAuth("tok")
        with pytest.raises(SafeguardError, match="does not support refresh"):
            auth.refresh(client)

    def test_repr_hides_token(self):
        r = repr(TokenAuth("secret-token"))
        assert "secret-token" not in r

    def test_dispose(self):
        auth = TokenAuth("tok")
        auth.dispose()
        with pytest.raises(RuntimeError, match="disposed"):
            auth.token.get_value()


# ---------------------------------------------------------------------------
# Provider resolution
# ---------------------------------------------------------------------------


class TestResolveProvider:
    """Test _resolve_provider — sync provider resolution with graceful fallback."""

    def test_resolves_provider_name(self):
        from pysafeguard.auth import _resolve_provider

        providers = [{"Name": "Local", "RstsProviderId": "local"}]
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = providers

        with patch("pysafeguard.auth._requests.get", return_value=mock_resp):
            result = _resolve_provider("host", "v4", "Local", False)
        assert result == "local"

    def test_falls_back_on_http_error(self):
        from pysafeguard.auth import _resolve_provider

        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 500

        with patch("pysafeguard.auth._requests.get", return_value=mock_resp):
            result = _resolve_provider("host", "v4", "my-provider", False)
        assert result == "my-provider"

    def test_falls_back_on_connection_error(self):
        from pysafeguard.auth import _resolve_provider

        with patch("pysafeguard.auth._requests.get", side_effect=ConnectionError("refused")):
            result = _resolve_provider("host", "v4", "my-provider", False)
        assert result == "my-provider"

    def test_falls_back_on_non_list_response(self):
        from pysafeguard.auth import _resolve_provider

        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"error": "unexpected"}

        with patch("pysafeguard.auth._requests.get", return_value=mock_resp):
            result = _resolve_provider("host", "v4", "my-provider", False)
        assert result == "my-provider"

    def test_raises_on_no_match(self):
        """When the API succeeds but provider isn't found, raise (not fallback)."""
        from pysafeguard.auth import _resolve_provider

        providers = [{"Name": "Local", "RstsProviderId": "local"}]
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = providers

        with patch("pysafeguard.auth._requests.get", return_value=mock_resp):
            with pytest.raises(SafeguardError, match="Unable to find provider"):
                _resolve_provider("host", "v4", "nonexistent", False)
