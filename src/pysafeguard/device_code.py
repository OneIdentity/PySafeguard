# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Device Authorization Grant login for Safeguard.

Implements the OAuth 2.0 Device Authorization Grant (RFC 8628) against the
Safeguard rSTS endpoints. This is a headless, browser-less interactive login:
the SDK requests a device code, hands the verification URL and user code to a
caller-supplied callback, then polls until the user authenticates in their own
browser (on any device) or the code expires.

The library performs **no** display I/O and never opens a browser — presenting
the :class:`~pysafeguard.data_types.DeviceCodeInfo` is the caller's
responsibility.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable

from requests import Session

from .data_types import DeviceCodeInfo
from .errors import SafeguardError
from .pkce import DEFAULT_TIMEOUT, _post_login_response

# Default scope matches the other Safeguard SDKs (primary local provider).
DEFAULT_DEVICE_CODE_SCOPE = "rsts:sts:primaryproviderid:local"

# RFC 8628 device-code grant type used when polling the token endpoint.
DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

# Number of seconds added to the polling interval when the server returns slow_down.
_SLOW_DOWN_INCREMENT = 5

# Case-insensitive substring the appliance returns (as HTML or JSON) when the
# Device Code grant type is not enabled.
_DISABLED_GRANT_MARKER = "device code grant type is not allowed"

_DISABLED_GRANT_MESSAGE = (
    "OAuth2 device code grant type is not allowed. Enable it on the appliance under "
    "Settings -> OAuth 2.0 Grant Types / API Settings by adding 'DeviceCode' to the "
    "'Allowed OAuth2 Grant Types' setting."
)


def get_device_code_token(
    appliance: str,
    *,
    on_device_code: Callable[[DeviceCodeInfo], None],
    scope: str | None = None,
    client_id: str = "",
    polling_interval: int = 5,
    is_cancelled: Callable[[], bool] | None = None,
    verify: bool | str = True,
    api_version: str = "v4",
) -> str:
    """Perform the Device Authorization Grant flow and return a Safeguard user token.

    :param appliance: Network address (hostname or IP) of the Safeguard appliance.
    :param on_device_code: Required callback invoked exactly once with a
        :class:`~pysafeguard.data_types.DeviceCodeInfo`. The caller decides how to
        display it; the library prints nothing and never opens a browser.
    :param scope: rSTS scope; defaults to ``rsts:sts:primaryproviderid:local``.
    :param client_id: OAuth client id; defaults to ``""`` like the other SDKs.
    :param polling_interval: Seconds between poll attempts; auto-bumps on ``slow_down``.
    :param is_cancelled: Optional callback; when it returns truthy the login aborts.
    :param verify: A path to a CA certificate file, or ``False`` to disable TLS verification.
    :param api_version: API version to use (default ``"v4"``).
    :returns: A Safeguard user token string.
    :raises SafeguardError: If the grant is disabled, the user denies or never
        completes authentication, the code expires, or the login is cancelled.
    """
    if polling_interval <= 0:
        raise SafeguardError("polling_interval must be a positive number of seconds.")

    resolved_scope = scope if scope is not None else DEFAULT_DEVICE_CODE_SCOPE

    with Session() as session:
        session.verify = verify

        device_login = _request_device_code(session, appliance, client_id, resolved_scope)
        device_code = _extract_device_code(device_login)
        info = DeviceCodeInfo.from_device_login(device_login, default_interval=polling_interval)

        on_device_code(info)

        rsts_access_token = _poll_for_token(
            session,
            appliance,
            device_code,
            client_id,
            expires_in=info.expires_in,
            polling_interval=polling_interval,
            is_cancelled=is_cancelled,
        )

        return _post_login_response(session, appliance, rsts_access_token, api_version)


def _request_device_code(session: Session, appliance: str, client_id: str, scope: str) -> dict[str, object]:
    """Request a device code from rSTS, detecting the disabled-grant condition."""
    url = f"https://{appliance}/RSTS/oauth2/DeviceLogin"
    body = {"client_id": client_id, "scope": scope}

    resp = session.post(url, json=body, headers={"Accept": "application/json"}, timeout=DEFAULT_TIMEOUT)

    if not resp.ok:
        # Disabled-grant responses are HTML, not JSON — substring match only.
        _raise_for_disabled_grant(resp.text, resp.status_code)
        raise SafeguardError(
            f"Failed to start device code login: {resp.status_code} {resp.text}",
            status_code=resp.status_code,
            response_body=resp.text,
        )

    data: object = resp.json()
    if not isinstance(data, dict):
        raise SafeguardError("Unexpected response from RSTS DeviceLogin endpoint")
    return data


def _poll_for_token(
    session: Session,
    appliance: str,
    device_code: str,
    client_id: str,
    *,
    expires_in: int,
    polling_interval: int,
    is_cancelled: Callable[[], bool] | None,
) -> str:
    """Poll the rSTS token endpoint until success, denial, expiry, or deadline."""
    url = f"https://{appliance}/RSTS/oauth2/token"
    body = {
        "grant_type": DEVICE_CODE_GRANT_TYPE,
        "device_code": device_code,
        "client_id": client_id,
    }

    # Fixed deadline from the appliance's expires_in; never extended.
    deadline = time.monotonic() + expires_in
    interval = polling_interval

    while True:
        _check_cancelled(is_cancelled)
        if time.monotonic() >= deadline:
            raise SafeguardError("Device code login timed out before the user completed authentication.")

        resp = session.post(url, json=body, headers={"Accept": "application/json"}, timeout=DEFAULT_TIMEOUT)
        outcome, access_token = _interpret_poll_result(resp.status_code, resp.text)
        if outcome == "success":
            return access_token
        if outcome == "slow_down":
            interval += _SLOW_DOWN_INCREMENT

        _check_cancelled(is_cancelled)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SafeguardError("Device code login timed out before the user completed authentication.")
        # Sleep only up to the remaining deadline so expiry is not overshot.
        time.sleep(min(interval, remaining))


def _check_cancelled(is_cancelled: Callable[[], bool] | None) -> None:
    """Raise if the caller-supplied cancel hook reports cancellation."""
    if is_cancelled is not None and is_cancelled():
        raise SafeguardError("Device code login was cancelled before completion.")


def _extract_device_code(data: dict[str, object]) -> str:
    """Pull the internal ``device_code`` out of the DeviceLogin response."""
    device_code = data.get("device_code")
    if not isinstance(device_code, str) or not device_code:
        raise SafeguardError("RSTS DeviceLogin response did not contain a device_code")
    return device_code


def _raise_for_disabled_grant(body: str, status_code: int) -> None:
    """Raise a clear error if ``body`` indicates the Device Code grant is disabled.

    The disabled-grant response is HTML on the DeviceLogin endpoint, so this uses
    a case-insensitive substring match and never parses JSON.
    """
    if body and _DISABLED_GRANT_MARKER in body.lower():
        raise SafeguardError(_DISABLED_GRANT_MESSAGE, status_code=status_code, response_body=body)


def _parse_poll_error(body: str) -> str:
    """Extract the RFC 8628 ``error`` code from a JSON token-endpoint error body."""
    try:
        data: object = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return ""
    if isinstance(data, dict):
        error = data.get("error")
        if isinstance(error, str):
            return error
    return ""


def _interpret_poll_result(status_code: int, body: str) -> tuple[str, str]:
    """Interpret an rSTS device-code token poll response.

    :returns: ``(outcome, access_token)`` where ``outcome`` is ``"success"``,
        ``"authorization_pending"``, or ``"slow_down"``. ``access_token`` is only
        populated for ``"success"``.
    :raises SafeguardError: For terminal errors (denied, expired, disabled, or unknown).
    """
    if 200 <= status_code < 300:
        try:
            data: object = json.loads(body)
        except (json.JSONDecodeError, TypeError) as ex:
            raise SafeguardError("Unexpected response from RSTS token endpoint") from ex
        if not isinstance(data, dict):
            raise SafeguardError("Unexpected response from RSTS token endpoint")
        access_token = data.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise SafeguardError("RSTS token response did not contain an access_token")
        return "success", access_token

    error = _parse_poll_error(body)
    if error == "authorization_pending":
        return "authorization_pending", ""
    if error == "slow_down":
        return "slow_down", ""
    if error == "access_denied":
        raise SafeguardError(
            "Device code login was denied by the user.",
            status_code=status_code,
            response_body=body,
        )
    if error == "expired_token":
        raise SafeguardError(
            "The device code expired before the user completed authentication.",
            status_code=status_code,
            response_body=body,
        )

    _raise_for_disabled_grant(body, status_code)
    raise SafeguardError(
        f"Device code login failed: {error or body}",
        status_code=status_code,
        response_body=body,
    )
