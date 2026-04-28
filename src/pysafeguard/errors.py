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
        message = f"{resp.status_code} {resp.reason}: {resp.request.method} {resp.url}\n{resp.text}"
        status_code = resp.status_code
        body = resp.text

        subclass = _STATUS_MAP.get(status_code, cls)
        return subclass(message, status_code=status_code, response_body=body)

    @classmethod
    def from_async_response(cls, resp: ClientResponse) -> ApiError:
        """Create an ApiError from an async ``aiohttp.ClientResponse``.

        .. note::
            The response body must have been read (``await resp.read()``)
            before calling this method, or the body will be empty.
        """
        body = resp._body.decode("utf-8", errors="replace") if resp._body else ""  # noqa: SLF001
        message = f"{resp.status} {resp.reason}: {resp.method} {resp.url}\n{body}"
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
