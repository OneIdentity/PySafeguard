# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Integration tests: Device Authorization Grant (RFC 8628) login (sync + async).

These tests require a live appliance and are auto-skipped when ``SPP_HOST`` is
unset. They follow the guaranteed end-to-end floor established by
SafeguardDotNet's ``Suite-DeviceCodeAuthentication``:

1. Save the appliance's ``Allowed OAuth2 Grant Types`` setting.
2. With the Device Code grant **disabled**, assert the clear disabled-grant error.
3. With the Device Code grant **enabled**, assert the verification URL is
   delivered to the required callback.
4. Restore the original setting.

Scripted no-human approval (LOCAL provider / NO MFA) is opt-in and may be
skipped if brittle. A human-in-the-loop fallback runs only when both
``SPP_HOST`` and ``SPP_DEVICE_CODE_INTERACTIVE=1`` are set.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

import pytest

from pysafeguard import (
    AsyncSafeguardClient,
    DeviceCodeAuth,
    DeviceCodeInfo,
    PkceAuth,
    SafeguardClient,
    Service,
)
from pysafeguard.async_device_code import async_get_device_code_token
from pysafeguard.device_code import get_device_code_token
from pysafeguard.errors import SafeguardError

pytestmark = pytest.mark.integration

_GRANT_SETTING = "Allowed OAuth2 Grant Types"
_DEVICE_CODE_GRANT = "DeviceCode"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_grant_value(client: SafeguardClient) -> str:
    for setting in client.get(Service.CORE, "Settings").json():
        if setting.get("Name") == _GRANT_SETTING:
            return str(setting.get("Value", ""))
    raise AssertionError(f"Could not find '{_GRANT_SETTING}' in appliance settings")


def _set_grant_value(client: SafeguardClient, value: str) -> None:
    client.put(Service.CORE, f"Settings/{_GRANT_SETTING}", json={"Value": value})


def _with_device_code(value: str, *, enabled: bool) -> str:
    grants = [g.strip() for g in value.split(",") if g.strip()]
    present = any(g.lower() == _DEVICE_CODE_GRANT.lower() for g in grants)
    if enabled and not present:
        grants.append(_DEVICE_CODE_GRANT)
    elif not enabled and present:
        grants = [g for g in grants if g.lower() != _DEVICE_CODE_GRANT.lower()]
    return ", ".join(grants)


@contextmanager
def _device_code_grant(client: SafeguardClient, *, enabled: bool) -> Iterator[None]:
    """Toggle the Device Code grant on the appliance and restore it afterward."""
    original = _get_grant_value(client)
    try:
        _set_grant_value(client, _with_device_code(original, enabled=enabled))
        yield
    finally:
        _set_grant_value(client, original)


@pytest.fixture()
def admin_client(spp_host: str, spp_username: str, spp_password: str, spp_verify: bool | str) -> Iterator[SafeguardClient]:
    """Authenticated client (PKCE, no ROG dependency) for toggling settings."""
    with SafeguardClient(spp_host, auth=PkceAuth("local", spp_username, spp_password), verify=spp_verify) as client:
        client.login()
        yield client


class _CancelAfterDisplay:
    """Captures the device-code display info, then cancels the poll loop."""

    def __init__(self) -> None:
        self.info: DeviceCodeInfo | None = None

    def on_device_code(self, info: DeviceCodeInfo) -> None:
        self.info = info

    def is_cancelled(self) -> bool:
        # Cancel as soon as the verification URL has been delivered.
        return self.info is not None


# ===========================================================================
# Guaranteed floor
# ===========================================================================


class TestDeviceCodeDisabledGrant:
    def test_disabled_grant_reports_clear_error(self, admin_client: SafeguardClient, spp_host: str, spp_verify: bool | str) -> None:
        with _device_code_grant(admin_client, enabled=False):
            collector = _CancelAfterDisplay()
            with pytest.raises(SafeguardError, match="not allowed"):
                get_device_code_token(
                    spp_host,
                    on_device_code=collector.on_device_code,
                    verify=spp_verify,
                )
            assert collector.info is None


class TestDeviceCodeEnabledGrant:
    def test_enabled_grant_delivers_verification_url(self, admin_client: SafeguardClient, spp_host: str, spp_verify: bool | str) -> None:
        with _device_code_grant(admin_client, enabled=True):
            collector = _CancelAfterDisplay()
            # The login is cancelled right after the URL is delivered, so this
            # asserts the enabled path produces a verification URL without
            # requiring a human to approve.
            with pytest.raises(SafeguardError, match="cancelled"):
                get_device_code_token(
                    spp_host,
                    on_device_code=collector.on_device_code,
                    is_cancelled=collector.is_cancelled,
                    verify=spp_verify,
                )
            assert collector.info is not None
            assert collector.info.verification_uri
            assert collector.info.user_code
            assert collector.info.expires_in > 0

    async def test_async_enabled_grant_delivers_verification_url(self, admin_client: SafeguardClient, spp_host: str, spp_verify: bool | str) -> None:
        with _device_code_grant(admin_client, enabled=True):
            collector = _CancelAfterDisplay()
            with pytest.raises(SafeguardError, match="cancelled"):
                await async_get_device_code_token(
                    spp_host,
                    on_device_code=collector.on_device_code,
                    is_cancelled=collector.is_cancelled,
                    verify=spp_verify,
                )
            assert collector.info is not None
            assert collector.info.verification_uri
            assert collector.info.user_code


# ===========================================================================
# Interactive fallback (human approves in a browser)
# ===========================================================================


_INTERACTIVE = os.environ.get("SPP_DEVICE_CODE_INTERACTIVE") == "1"


@pytest.mark.skipif(not _INTERACTIVE, reason="set SPP_DEVICE_CODE_INTERACTIVE=1 to run the human-approval device code test")
class TestDeviceCodeInteractive:
    def test_interactive_login_sync(self, admin_client: SafeguardClient, spp_host: str, spp_verify: bool | str) -> None:
        def show(info: DeviceCodeInfo) -> None:
            print("\n[device code] Open this URL in a browser and approve the login:")
            print(f"  {info.verification_uri_complete}")
            print(f"  Verification URL: {info.verification_uri}")
            print(f"  User code:        {info.user_code}\n")

        with _device_code_grant(admin_client, enabled=True):
            with SafeguardClient(spp_host, auth=DeviceCodeAuth(show), verify=spp_verify) as client:
                resp = client.get(Service.CORE, "Me")
                assert resp.status_code == 200

    async def test_interactive_login_async(self, admin_client: SafeguardClient, spp_host: str, spp_verify: bool | str) -> None:
        def show(info: DeviceCodeInfo) -> None:
            print("\n[device code] Open this URL in a browser and approve the login:")
            print(f"  {info.verification_uri_complete}")
            print(f"  User code: {info.user_code}\n")

        with _device_code_grant(admin_client, enabled=True):
            async with AsyncSafeguardClient(spp_host, auth=DeviceCodeAuth(show), verify=spp_verify) as client:
                resp = await client.get(Service.CORE, "Me")
                assert resp.status == 200
