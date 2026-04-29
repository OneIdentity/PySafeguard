# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Unit tests for PKCE crypto helpers and authorization code extraction.

These test the pure functions in pkce.py without requiring network access.
"""

import base64
import hashlib
import json

import pytest

from pysafeguard.pkce import (
    _base64url,
    _check_mfa_result,
    _check_secondary_required,
    _extract_authorization_code,
    _extract_mfa_state,
    _generate_code_challenge,
    _generate_code_verifier,
    _generate_csrf_token,
    _match_provider,
)


class TestBase64Url:
    def test_no_padding(self):
        """base64url output should not contain trailing '=' characters."""
        result = _base64url(b"\x00\x01\x02")
        assert "=" not in result

    def test_url_safe_characters(self):
        """Output should use - and _ instead of + and /."""
        # Use bytes that produce + and / in standard base64
        data = b"\xfb\xef\xbe"  # Standard: ++++ → base64url: --__
        result = _base64url(data)
        assert "+" not in result
        assert "/" not in result

    def test_round_trip(self):
        """Verify we can decode back to original bytes."""
        original = b"hello world"
        encoded = _base64url(original)
        # Add padding back for decoding
        padded = encoded + "=" * (4 - len(encoded) % 4) if len(encoded) % 4 else encoded
        decoded = base64.urlsafe_b64decode(padded)
        assert decoded == original

    def test_empty_bytes(self):
        result = _base64url(b"")
        assert result == ""


class TestGenerateCsrfToken:
    def test_returns_string(self):
        token = _generate_csrf_token()
        assert isinstance(token, str)
        assert len(token) > 0

    def test_uniqueness(self):
        tokens = {_generate_csrf_token() for _ in range(10)}
        assert len(tokens) == 10  # All unique


class TestGenerateCodeVerifier:
    def test_returns_string(self):
        verifier = _generate_code_verifier()
        assert isinstance(verifier, str)
        assert len(verifier) > 0

    def test_uniqueness(self):
        verifiers = {_generate_code_verifier() for _ in range(10)}
        assert len(verifiers) == 10


class TestGenerateCodeChallenge:
    def test_is_sha256_of_verifier(self):
        """Code challenge should be base64url(SHA256(ASCII(verifier)))."""
        verifier = "test-verifier-string"
        challenge = _generate_code_challenge(verifier)

        # Manually compute expected value
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        assert challenge == expected

    def test_deterministic(self):
        verifier = _generate_code_verifier()
        c1 = _generate_code_challenge(verifier)
        c2 = _generate_code_challenge(verifier)
        assert c1 == c2

    def test_different_verifiers_produce_different_challenges(self):
        c1 = _generate_code_challenge("verifier-a")
        c2 = _generate_code_challenge("verifier-b")
        assert c1 != c2


class TestExtractAuthorizationCode:
    def test_extracts_code_from_relying_party_url(self):
        body = json.dumps({"RelyingPartyUrl": "https://host/callback?code=abc123&state=xyz"})
        assert _extract_authorization_code(body) == "abc123"

    def test_missing_relying_party_url_raises(self):
        body = json.dumps({"Other": "data"})
        with pytest.raises(Exception, match="RelyingPartyUrl"):
            _extract_authorization_code(body)

    def test_missing_code_param_raises(self):
        body = json.dumps({"RelyingPartyUrl": "https://host/callback?state=xyz"})
        with pytest.raises(Exception, match="authorization code"):
            _extract_authorization_code(body)

    def test_non_json_raises(self):
        with pytest.raises(Exception, match="parse"):
            _extract_authorization_code("not json at all")

    def test_non_dict_json_raises(self):
        with pytest.raises(Exception, match="parse"):
            _extract_authorization_code("[1, 2, 3]")


class TestMatchProvider:
    """Tests for _match_provider — 3-pass provider matching logic."""

    PROVIDERS = [
        {"Name": "Local", "RstsProviderId": "local"},
        {"Name": "Active Directory", "RstsProviderId": "ad.example.com"},
        {"Name": "LDAP Corp", "RstsProviderId": "ldap://corp.example.com"},
    ]

    def test_exact_rsts_id_match(self):
        assert _match_provider(self.PROVIDERS, "local") == "local"

    def test_exact_rsts_id_case_insensitive(self):
        assert _match_provider(self.PROVIDERS, "LOCAL") == "local"

    def test_exact_name_match(self):
        assert _match_provider(self.PROVIDERS, "Active Directory") == "ad.example.com"

    def test_exact_name_case_insensitive(self):
        assert _match_provider(self.PROVIDERS, "active directory") == "ad.example.com"

    def test_substring_match(self):
        assert _match_provider(self.PROVIDERS, "corp") == "ldap://corp.example.com"

    def test_no_match_raises(self):
        with pytest.raises(Exception, match="Unable to find provider"):
            _match_provider(self.PROVIDERS, "nonexistent")

    def test_no_match_error_format(self):
        """Error message should list providers in 'RstsProviderId [Name]' format (matching safeguard-ps)."""
        providers = [{"Name": "Local", "RstsProviderId": "local"}]
        with pytest.raises(Exception, match=r"local \[Local\]"):
            _match_provider(providers, "nonexistent")

    def test_empty_list_raises(self):
        with pytest.raises(Exception, match="Unable to find provider"):
            _match_provider([], "local")

    def test_non_dict_items_skipped(self):
        providers: list[object] = ["garbage", 42, {"Name": "Valid", "RstsProviderId": "valid-id"}]
        assert _match_provider(providers, "valid-id") == "valid-id"

    def test_rsts_id_preferred_over_name(self):
        """If a provider's RstsProviderId matches exactly, prefer it over a Name match."""
        providers = [
            {"Name": "local", "RstsProviderId": "some-other-id"},
            {"Name": "Other", "RstsProviderId": "local"},
        ]
        assert _match_provider(providers, "local") == "local"


class TestCheckSecondaryRequired:
    """Tests for _check_secondary_required — MFA detection from primary response."""

    def test_no_mfa_returns_none(self):
        body = json.dumps({"SomeField": "value"})
        assert _check_secondary_required(body, None) is None

    def test_mfa_required_with_password(self):
        body = json.dumps({"SecondaryProviderID": "totp-provider"})
        assert _check_secondary_required(body, "123456") == "totp-provider"

    def test_mfa_required_without_password_raises(self):
        body = json.dumps({"SecondaryProviderID": "totp-provider"})
        with pytest.raises(Exception, match="Multi-factor authentication is required"):
            _check_secondary_required(body, None)

    def test_non_json_returns_none(self):
        assert _check_secondary_required("not json", "password") is None

    def test_non_dict_json_returns_none(self):
        assert _check_secondary_required("[1,2,3]", "password") is None

    def test_empty_secondary_provider_returns_none(self):
        body = json.dumps({"SecondaryProviderID": ""})
        assert _check_secondary_required(body, "password") is None


class TestExtractMfaState:
    """Tests for _extract_mfa_state — extract MFA state from init response."""

    def test_extracts_state(self):
        body = json.dumps({"State": "abc123"})
        assert _extract_mfa_state(body, 200) == "abc123"

    def test_extracts_state_from_203(self):
        body = json.dumps({"State": "xyz"})
        assert _extract_mfa_state(body, 203) == "xyz"

    def test_missing_state_returns_empty(self):
        body = json.dumps({"Other": "data"})
        assert _extract_mfa_state(body, 200) == ""

    def test_non_json_returns_empty(self):
        assert _extract_mfa_state("not json", 200) == ""

    def test_non_2xx_returns_empty(self):
        body = json.dumps({"State": "abc"})
        assert _extract_mfa_state(body, 500) == ""


class TestCheckMfaResult:
    """Tests for _check_mfa_result — validate MFA authentication response."""

    def test_200_success_no_raise(self):
        _check_mfa_result("", 200)

    def test_203_with_message_raises(self):
        body = json.dumps({"Message": "Invalid OTP"})
        with pytest.raises(Exception, match="Invalid OTP"):
            _check_mfa_result(body, 203)

    def test_203_with_raw_text_raises(self):
        with pytest.raises(Exception, match="some error text"):
            _check_mfa_result("some error text", 203)

    def test_203_with_non_json_raises(self):
        with pytest.raises(Exception, match="Multi-factor authentication failed"):
            _check_mfa_result("", 203)

    def test_4xx_raises_with_status(self):
        with pytest.raises(Exception, match="Multi-factor authentication failed"):
            _check_mfa_result("bad request", 400)

    def test_success_range_no_raise(self):
        _check_mfa_result("", 201)
