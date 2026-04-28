"""Unit tests for PKCE crypto helpers and authorization code extraction.

These test the pure functions in pkce.py without requiring network access.
"""

import base64
import hashlib
import json

import pytest

from pysafeguard.pkce import (
    _base64url,
    _extract_authorization_code,
    _generate_code_challenge,
    _generate_code_verifier,
    _generate_csrf_token,
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
        body = json.dumps({
            "RelyingPartyUrl": "https://host/callback?code=abc123&state=xyz"
        })
        assert _extract_authorization_code(body) == "abc123"

    def test_missing_relying_party_url_raises(self):
        body = json.dumps({"Other": "data"})
        with pytest.raises(Exception, match="RelyingPartyUrl"):
            _extract_authorization_code(body)

    def test_missing_code_param_raises(self):
        body = json.dumps({
            "RelyingPartyUrl": "https://host/callback?state=xyz"
        })
        with pytest.raises(Exception, match="authorization code"):
            _extract_authorization_code(body)

    def test_non_json_raises(self):
        with pytest.raises(Exception, match="parse"):
            _extract_authorization_code("not json at all")

    def test_non_dict_json_raises(self):
        with pytest.raises(Exception, match="parse"):
            _extract_authorization_code("[1, 2, 3]")
