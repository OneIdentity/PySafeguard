# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Regression tests for D-013 credential / response-body leak audit.

Per cross-cutting decision D-013 (see security-triage.md §3), the SDK must not
interpolate full upstream response bodies into exception messages. The full
body is still available to callers via :attr:`SafeguardError.response_body`,
but the human-facing ``str(exc)`` rendering — which is what typically lands
in logs, crash reporters, and SIEMs — must be truncated to keep accidental
leakage of secrets, PII, or large bodies bounded.

This module asserts the truncation on every code path that wraps an HTTP
response into a ``SafeguardError`` or ``ApiError``.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from pysafeguard.errors import ApiError, _MAX_BODY_IN_MESSAGE


def _make_response(
    status_code: int = 500, reason: str = "Internal Server Error", method: str = "POST", url: str = "https://host/service/core/v4/Endpoint", text: str = ""
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.reason = reason
    resp.url = url
    resp.text = text
    resp.request = SimpleNamespace(method=method)
    return resp


def test_message_truncated_when_body_exceeds_limit() -> None:
    """ApiError.from_response message must not contain the body verbatim past the limit."""
    long_body = "A" * (_MAX_BODY_IN_MESSAGE * 4)
    err = ApiError.from_response(_make_response(text=long_body))
    rendered = str(err)
    # Full body must NOT appear in the human message.
    assert long_body not in rendered
    # But the underlying response_body attribute keeps it intact for callers.
    assert err.response_body == long_body


def test_truncated_message_includes_ellipsis_marker() -> None:
    """The truncated message should carry an explicit marker so users know it was elided."""
    long_body = "B" * (_MAX_BODY_IN_MESSAGE * 2)
    err = ApiError.from_response(_make_response(text=long_body))
    rendered = str(err)
    assert "truncated" in rendered.lower() or "..." in rendered


def test_short_body_passed_through_verbatim() -> None:
    """Bodies at or below the limit must not be molested — they often carry the real error text."""
    short_body = '{"Code": 123, "Message": "Bad input"}'
    assert len(short_body) <= _MAX_BODY_IN_MESSAGE
    err = ApiError.from_response(_make_response(status_code=400, text=short_body))
    assert short_body in str(err)


def test_response_body_attribute_is_full_body() -> None:
    """Truncation is a display concern; the raw body is still on the exception."""
    body = "X" * 5000
    err = ApiError.from_response(_make_response(text=body))
    assert err.response_body == body
    assert err.has_response


def test_pkce_failures_do_not_leak_full_body() -> None:
    """The PKCE / RSTS helpers also wrap response bodies; they must use the same truncation."""
    from pysafeguard import pkce as pkce_mod

    # Inspect the source of pkce.py for any unbounded `{...text}` interpolation that
    # would bypass the truncation helper. This is a static guardrail.
    import inspect

    src = inspect.getsource(pkce_mod)
    # Any place that interpolates a raw .text body into an f-string message
    # is suspect. The fix funnels through _truncate_for_message, so the only
    # acceptable forms are ones that call that helper or use response_body=
    # alone (the helper truncates when building messages).
    forbidden_patterns = (
        "{resp.text}",
        "{claims_resp.text}",
        "{primary_resp.text}",
        "{mfa_resp.text}",
        "{init_resp.text}",
    )
    for pat in forbidden_patterns:
        assert pat not in src, f"pkce.py interpolates `{pat}` into a message verbatim; route through errors._truncate_for_message instead to honor D-013."


def test_truncation_helper_preserves_legitimate_field_names() -> None:
    """D-013 negative test: truncation must NOT mask legitimate API body field names.

    The helper is allowed to truncate length, but it must never substring-redact
    field names that happen to contain 'password', 'apikey', etc. Those are real
    Safeguard payload fields and must round-trip unchanged when the body is short.
    """
    legitimate = '{"PasswordRulesPolicyId": 5, "ApiKeyName": "svc", "RequirePasswordChange": true, "PasswordHistoryDepth": 10, "PrivateKeyFormat": "OpenSsh"}'
    err = ApiError.from_response(_make_response(status_code=400, text=legitimate))
    rendered = str(err)
    for needle in ("PasswordRulesPolicyId", "ApiKeyName", "RequirePasswordChange", "PasswordHistoryDepth", "PrivateKeyFormat"):
        assert needle in rendered, f"{needle} must pass through the message unchanged (D-013)"
