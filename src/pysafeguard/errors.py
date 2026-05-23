# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Exception hierarchy for PySafeguard.

All exceptions inherit from :class:`SafeguardError` so callers can catch
the base class for blanket error handling or specific subclasses for
targeted recovery.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiohttp import ClientResponse
    from requests import Response


# D-013: cap how much of a response body we splice into an exception's human-facing
# message. The full body remains available to callers via :attr:`SafeguardError.response_body`
# for diagnostic use; this limit only bounds what lands in ``str(exc)`` (the form that
# typically reaches logs, crash reporters, and SIEMs). Truncation — not field-level
# redaction — is the chosen mitigation: it never wrongly masks legitimate Safeguard
# payload fields like ``PasswordRulesPolicyId``, ``ApiKeyName``, or
# ``RequirePasswordChange``.
_MAX_BODY_IN_MESSAGE = 200


def _truncate_for_message(body: str | None, limit: int = _MAX_BODY_IN_MESSAGE) -> str:
    """Bound a response body for inclusion in a human-readable exception message.

    Returns ``body`` unchanged if it is already at or under ``limit`` characters,
    otherwise returns the first ``limit`` characters followed by a
    ``... (truncated, N total chars)`` marker so the reader knows it was elided.
    """
    if body is None:
        return ""
    if len(body) <= limit:
        return body
    return f"{body[:limit]}... (truncated, {len(body)} total chars)"


class SafeguardError(Exception):
    """Base exception for all PySafeguard errors.

    :ivar status_code: HTTP status code from the API response, if available.
    :ivar error_code: Safeguard-specific error code parsed from JSON response body.
    :ivar error_message: Human-readable error message parsed from JSON response body.
    :ivar response_body: Raw response body string, if available.
    """

    status_code: int | None
    error_code: int | None
    error_message: str | None
    response_body: str | None

    def __init__(
        self,
        message: str = "",
        *,
        status_code: int | None = None,
        response_body: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.error_code = None
        self.error_message = None
        self.response_body = response_body

        if response_body is not None:
            self._parse_response(response_body)

        display = message or self.error_message or ""
        super().__init__(display)

    @property
    def has_response(self) -> bool:
        """Whether this exception includes a raw API response body."""
        return self.response_body is not None

    def _parse_response(self, response_body: str) -> None:
        """Attempt to extract structured error fields from a JSON response."""
        try:
            data: object = json.loads(response_body)
            if isinstance(data, dict):
                code = data.get("Code")
                if code is not None:
                    self.error_code = int(code)
                message = data.get("Message")
                if message is not None:
                    self.error_message = str(message)
                elif "error" in data:
                    self.error_message = str(data["error"])
        except (json.JSONDecodeError, TypeError, ValueError):
            pass


class ApiError(SafeguardError):
    """HTTP error response from the Safeguard API.

    Raised when a request returns a non-success status code.
    """

    @classmethod
    def from_response(cls, resp: Response) -> ApiError:
        """Create an ApiError from a sync ``requests.Response``."""
        body = resp.text
        message = f"{resp.status_code} {resp.reason}: {resp.request.method} {resp.url}\n{_truncate_for_message(body)}"
        status_code = resp.status_code

        subclass = _STATUS_MAP.get(status_code, cls)
        return subclass(message, status_code=status_code, response_body=body)

    @classmethod
    def from_async_response(cls, resp: ClientResponse, body: str) -> ApiError:
        """Create an ApiError from an async ``aiohttp.ClientResponse``.

        :param resp: The aiohttp response.
        :param body: The response body text (must be read by the caller
            with ``await resp.text()`` before calling this method).
        """
        message = f"{resp.status} {resp.reason}: {resp.method} {resp.url}\n{_truncate_for_message(body)}"
        status_code = resp.status

        subclass = _STATUS_MAP.get(status_code, cls)
        return subclass(message, status_code=status_code, response_body=body)


class AuthenticationError(ApiError):
    """401 Unauthorized — authentication failed or token expired."""


class AuthorizationError(ApiError):
    """403 Forbidden — insufficient permissions."""


class NotFoundError(ApiError):
    """404 Not Found — the requested resource does not exist."""


class TransportError(SafeguardError):
    """Network or connection-level failure (no HTTP response)."""


# Map HTTP status codes to specific exception subclasses
_STATUS_MAP: dict[int, type[ApiError]] = {
    401: AuthenticationError,
    403: AuthorizationError,
    404: NotFoundError,
}
