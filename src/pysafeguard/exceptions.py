from __future__ import annotations

import json


class SafeguardException(Exception):
    """Base exception for all Safeguard SDK errors.

    Carries structured error information from Safeguard API responses.

    :ivar status_code: HTTP status code from the API response, if available.
    :ivar error_code: Safeguard-specific error code parsed from JSON response body.
    :ivar error_message: Human-readable error message parsed from JSON response body.
    :ivar response: Raw response body string, if available.
    """

    status_code: int | None
    error_code: int | None
    error_message: str | None
    response: str | None

    def __init__(
        self,
        message: str = "",
        *,
        status_code: int | None = None,
        response: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.error_code = None
        self.error_message = None
        self.response = response

        if response is not None:
            self._parse_response(response)

        display = message or self.error_message or ""
        super().__init__(display)

    @property
    def has_response(self) -> bool:
        """Whether this exception includes a raw API response body."""
        return self.response is not None

    def _parse_response(self, response: str) -> None:
        """Attempt to extract structured error fields from a JSON response."""
        try:
            data: object = json.loads(response)
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
