# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Async Device Authorization Grant login for Safeguard.

Async mirror of :mod:`pysafeguard.device_code` using ``aiohttp`` instead of
``requests``. Reuses the shared constants and validators from the sync module
the way :mod:`pysafeguard.async_pkce` reuses :mod:`pysafeguard.pkce`.

In addition to the optional ``is_cancelled`` hook, this implementation honors
``asyncio`` cancellation: :class:`asyncio.CancelledError` is never caught or
suppressed. If ``on_device_code`` returns an awaitable it is awaited; the sync
flow still requires a plain function.
"""

from __future__ import annotations

import asyncio
import inspect
import ssl
import time
from collections.abc import Awaitable, Callable

from aiohttp import ClientSession, ClientTimeout

from .data_types import DeviceCodeInfo
from .device_code import (
    DEFAULT_DEVICE_CODE_SCOPE,
    DEVICE_CODE_GRANT_TYPE,
    _SLOW_DOWN_INCREMENT,
    _extract_device_code,
    _interpret_poll_result,
    _raise_for_disabled_grant,
)
from .errors import SafeguardError
from .pkce import DEFAULT_TIMEOUT
from .async_pkce import _async_post_login_response, _create_ssl_context


async def async_get_device_code_token(
    appliance: str,
    *,
    on_device_code: Callable[[DeviceCodeInfo], None | Awaitable[None]],
    scope: str | None = None,
    client_id: str = "",
    polling_interval: int = 5,
    is_cancelled: Callable[[], bool] | None = None,
    verify: bool | str = True,
    api_version: str = "v4",
) -> str:
    """Async Device Authorization Grant flow returning a Safeguard user token.

    :param appliance: Network address (hostname or IP) of the Safeguard appliance.
    :param on_device_code: Required callback invoked exactly once with a
        :class:`~pysafeguard.data_types.DeviceCodeInfo`. It may be a plain function
        or a coroutine function; if it returns an awaitable the result is awaited.
        The library prints nothing and never opens a browser.
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
    ssl_context = _create_ssl_context(verify)
    timeout = ClientTimeout(total=DEFAULT_TIMEOUT)

    async with ClientSession() as session:
        device_login = await _async_request_device_code(session, appliance, client_id, resolved_scope, ssl_context, timeout)
        device_code = _extract_device_code(device_login)
        info = DeviceCodeInfo.from_device_login(device_login, default_interval=polling_interval)

        result = on_device_code(info)
        if inspect.isawaitable(result):
            await result

        rsts_access_token = await _async_poll_for_token(
            session,
            appliance,
            device_code,
            client_id,
            expires_in=info.expires_in,
            polling_interval=polling_interval,
            is_cancelled=is_cancelled,
            ssl_context=ssl_context,
            timeout=timeout,
        )

        return await _async_post_login_response(session, appliance, rsts_access_token, api_version, ssl_context, timeout)


async def _async_request_device_code(
    session: ClientSession,
    appliance: str,
    client_id: str,
    scope: str,
    ssl_context: ssl.SSLContext | bool,
    timeout: ClientTimeout,
) -> dict[str, object]:
    """Request a device code from rSTS (async), detecting the disabled-grant condition."""
    url = f"https://{appliance}/RSTS/oauth2/DeviceLogin"
    body = {"client_id": client_id, "scope": scope}

    async with session.post(url, json=body, headers={"Accept": "application/json"}, ssl=ssl_context, timeout=timeout) as resp:
        status = resp.status
        if not (200 <= status < 300):
            text = await resp.text()
            # Disabled-grant responses are HTML, not JSON — substring match only.
            _raise_for_disabled_grant(text, status)
            raise SafeguardError(
                f"Failed to start device code login: {status} {text}",
                status_code=status,
                response_body=text,
            )
        data: object = await resp.json(content_type=None)

    if not isinstance(data, dict):
        raise SafeguardError("Unexpected response from RSTS DeviceLogin endpoint")
    return data


async def _async_poll_for_token(
    session: ClientSession,
    appliance: str,
    device_code: str,
    client_id: str,
    *,
    expires_in: int,
    polling_interval: int,
    is_cancelled: Callable[[], bool] | None,
    ssl_context: ssl.SSLContext | bool,
    timeout: ClientTimeout,
) -> str:
    """Poll the rSTS token endpoint until success, denial, expiry, or deadline (async)."""
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

        async with session.post(url, json=body, headers={"Accept": "application/json"}, ssl=ssl_context, timeout=timeout) as resp:
            status = resp.status
            text = await resp.text()

        outcome, access_token = _interpret_poll_result(status, text)
        if outcome == "success":
            return access_token
        if outcome == "slow_down":
            interval += _SLOW_DOWN_INCREMENT

        _check_cancelled(is_cancelled)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SafeguardError("Device code login timed out before the user completed authentication.")
        # Sleep only up to the remaining deadline so expiry is not overshot.
        await asyncio.sleep(min(interval, remaining))


def _check_cancelled(is_cancelled: Callable[[], bool] | None) -> None:
    """Raise if the caller-supplied cancel hook reports cancellation."""
    if is_cancelled is not None and is_cancelled():
        raise SafeguardError("Device code login was cancelled before completion.")
