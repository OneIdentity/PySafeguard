# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Authentication strategy objects for Safeguard.

Each auth class encapsulates credentials and knows how to authenticate
(and optionally refresh) against a Safeguard appliance. They are passed
to :class:`~pysafeguard.client.SafeguardClient` or
:class:`~pysafeguard.async_client.AsyncSafeguardClient` via the ``auth``
parameter.

Example::

    from pysafeguard import SafeguardClient, PasswordAuth

    client = SafeguardClient("appliance.example.com", auth=PasswordAuth("local", "admin", "secret"))
    client.login()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import requests as _requests

from .errors import SafeguardError
from .hidden_string import HiddenString
from .pkce import _match_provider
from .utility import JsonType

if TYPE_CHECKING:
    from .async_client import AsyncSafeguardClient
    from .client import SafeguardClient


# ---------------------------------------------------------------------------
# Auth protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Auth(Protocol):
    """Protocol that all authentication strategies implement."""

    @property
    def can_refresh(self) -> bool:
        """Whether this auth strategy supports token refresh."""
        ...

    def authenticate(self, client: SafeguardClient) -> str:
        """Authenticate and return a Safeguard user token.

        :param client: The client to authenticate against (used for its
            host, verify, and low-level request transport).
        :returns: A user token string.
        """
        ...

    def refresh(self, client: SafeguardClient) -> str:
        """Re-authenticate and return a fresh user token.

        :param client: The client to authenticate against.
        :returns: A fresh user token string.
        :raises SafeguardError: If this auth strategy cannot refresh.
        """
        ...

    async def async_authenticate(self, client: AsyncSafeguardClient) -> str:
        """Async variant of :meth:`authenticate`."""
        ...

    async def async_refresh(self, client: AsyncSafeguardClient) -> str:
        """Async variant of :meth:`refresh`."""
        ...


# ---------------------------------------------------------------------------
# Provider resolution
# ---------------------------------------------------------------------------

_PROVIDER_TIMEOUT = 300


def _resolve_provider(host: str, api_version: str, provider: str, verify: bool | str) -> str:
    """Resolve a provider name/ID to an rSTS provider ID (sync).

    Queries the AuthenticationProviders endpoint and matches using the
    same 3-pass logic as safeguard-ps. Falls back to the provider
    string as-is if the endpoint is unreachable.
    """
    try:
        url = f"https://{host}/service/core/{api_version}/AuthenticationProviders"
        resp = _requests.get(url, headers={"Accept": "application/json"}, verify=verify, timeout=_PROVIDER_TIMEOUT)
        if not resp.ok:
            return provider
        providers: object = resp.json()
        if not isinstance(providers, list):
            return provider
        return _match_provider(providers, provider)
    except SafeguardError:
        raise
    except Exception:
        return provider


async def _async_resolve_provider(host: str, api_version: str, provider: str, verify: bool | str) -> str:
    """Resolve a provider name/ID to an rSTS provider ID (async).

    Async mirror of :func:`_resolve_provider`.
    """
    import ssl

    from aiohttp import ClientSession, ClientTimeout, CookieJar
    from truststore import SSLContext

    try:
        ssl_ctx: ssl.SSLContext | bool = False
        if verify is not False:
            ssl_ctx = SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if isinstance(verify, str):
                ssl_ctx.load_verify_locations(verify)

        timeout = ClientTimeout(total=_PROVIDER_TIMEOUT)
        url = f"https://{host}/service/core/{api_version}/AuthenticationProviders"
        async with ClientSession(cookie_jar=CookieJar(unsafe=True)) as session:
            async with session.get(url, headers={"Accept": "application/json"}, ssl=ssl_ctx, timeout=timeout) as resp:
                if resp.status >= 400:
                    return provider
                providers: object = await resp.json()

        if not isinstance(providers, list):
            return provider
        return _match_provider(providers, provider)
    except SafeguardError:
        raise
    except Exception:
        return provider


# ---------------------------------------------------------------------------
# Concrete auth strategies
# ---------------------------------------------------------------------------


def _rsts_token_exchange(client: SafeguardClient, body: dict[str, str], cert: tuple[str, str] | None = None) -> str:
    """Perform the rSTS → Core token exchange (sync) and return the user token."""
    from .data_types import HttpMethod, Service
    from .errors import ApiError
    from .utility import get_access_token, get_user_token

    json_body: JsonType = dict(body)
    resp = client.request(HttpMethod.POST, Service.RSTS, "oauth2/token", json=json_body, cert=cert)
    if resp.status_code != 200 or "application/json" not in resp.headers.get("content-type", ""):
        raise ApiError.from_response(resp)
    access_token = get_access_token(resp.json())

    resp = client.request(HttpMethod.POST, Service.CORE, "Token/LoginResponse", json={"StsAccessToken": access_token})
    if resp.status_code != 200 or "application/json" not in resp.headers.get("content-type", ""):
        raise ApiError.from_response(resp)
    return get_user_token(resp.json())


async def _async_rsts_token_exchange(client: AsyncSafeguardClient, body: dict[str, str], cert: tuple[str, str] | None = None) -> str:
    """Perform the rSTS → Core token exchange (async) and return the user token."""
    from .data_types import HttpMethod, Service
    from .errors import ApiError
    from .utility import get_access_token, get_user_token

    json_body: JsonType = dict(body)
    resp = await client.request(HttpMethod.POST, Service.RSTS, "oauth2/token", json=json_body, cert=cert)
    if resp.status != 200 or "application/json" not in resp.headers.get("content-type", ""):
        raise ApiError.from_async_response(resp, await resp.text())
    access_token = get_access_token(await resp.json(content_type=None))

    resp = await client.request(HttpMethod.POST, Service.CORE, "Token/LoginResponse", json={"StsAccessToken": access_token})
    if resp.status != 200 or "application/json" not in resp.headers.get("content-type", ""):
        raise ApiError.from_async_response(resp, await resp.text())
    return get_user_token(await resp.json(content_type=None))


@dataclass(frozen=True, eq=False)
class PasswordAuth:
    """Username/password authentication (Resource Owner Grant).

    Example::

        auth = PasswordAuth("local", "admin", "my-password")
        client = SafeguardClient("appliance", auth=auth)
    """

    provider: str
    username: str
    password: HiddenString = field(repr=False)

    def __init__(self, provider: str, username: str, password: str | HiddenString) -> None:
        object.__setattr__(self, "provider", provider)
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "password", password if isinstance(password, HiddenString) else HiddenString(password))

    @property
    def can_refresh(self) -> bool:
        return True

    def _build_body(self, resolved_provider: str) -> dict[str, str]:
        return {
            "scope": f"rsts:sts:primaryproviderid:{resolved_provider}",
            "grant_type": "password",
            "username": self.username,
            "password": self.password.get_value(),
        }

    def authenticate(self, client: SafeguardClient) -> str:
        resolved = _resolve_provider(client.host or "", client.api_version, self.provider, client.verify)
        return _rsts_token_exchange(client, self._build_body(resolved))

    def refresh(self, client: SafeguardClient) -> str:
        return self.authenticate(client)

    async def async_authenticate(self, client: AsyncSafeguardClient) -> str:
        resolved = await _async_resolve_provider(client.host or "", client.api_version, self.provider, client.verify)
        return await _async_rsts_token_exchange(client, self._build_body(resolved))

    async def async_refresh(self, client: AsyncSafeguardClient) -> str:
        return await self.async_authenticate(client)

    def dispose(self) -> None:
        """Zero out sensitive fields."""
        self.password.dispose()


@dataclass(frozen=True, eq=False)
class CertificateAuth:
    """Client certificate authentication.

    Example::

        auth = CertificateAuth("/path/cert.pem", "/path/key.pem")
        client = SafeguardClient("appliance", auth=auth)
    """

    cert_file: str
    key_file: str
    provider: str = "certificate"

    @property
    def can_refresh(self) -> bool:
        return True

    @property
    def cert_tuple(self) -> tuple[str, str]:
        return (self.cert_file, self.key_file)

    def _build_body(self, resolved_provider: str) -> dict[str, str]:
        return {
            "scope": f"rsts:sts:primaryproviderid:{resolved_provider}",
            "grant_type": "client_credentials",
        }

    def authenticate(self, client: SafeguardClient) -> str:
        resolved = _resolve_provider(client.host or "", client.api_version, self.provider, client.verify)
        return _rsts_token_exchange(client, self._build_body(resolved), cert=self.cert_tuple)

    def refresh(self, client: SafeguardClient) -> str:
        return self.authenticate(client)

    async def async_authenticate(self, client: AsyncSafeguardClient) -> str:
        resolved = await _async_resolve_provider(client.host or "", client.api_version, self.provider, client.verify)
        return await _async_rsts_token_exchange(client, self._build_body(resolved), cert=self.cert_tuple)

    async def async_refresh(self, client: AsyncSafeguardClient) -> str:
        return await self.async_authenticate(client)


@dataclass(frozen=True, eq=False)
class PkceAuth:
    """PKCE non-interactive browser flow authentication.

    Example::

        auth = PkceAuth("local", "admin", "my-password")
        client = SafeguardClient("appliance", auth=auth)

    .. note::
        If ``secondary_password`` is provided (MFA), the auth strategy
        cannot refresh because one-time passwords are not reusable.
    """

    provider: str
    username: str
    password: HiddenString = field(repr=False)
    secondary_password: HiddenString | None = field(repr=False, default=None)

    def __init__(
        self,
        provider: str,
        username: str,
        password: str | HiddenString,
        secondary_password: str | HiddenString | None = None,
    ) -> None:
        object.__setattr__(self, "provider", provider)
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "password", password if isinstance(password, HiddenString) else HiddenString(password))
        if secondary_password is not None:
            object.__setattr__(
                self,
                "secondary_password",
                secondary_password if isinstance(secondary_password, HiddenString) else HiddenString(secondary_password),
            )
        else:
            object.__setattr__(self, "secondary_password", None)

    @property
    def can_refresh(self) -> bool:
        return self.secondary_password is None

    def authenticate(self, client: SafeguardClient) -> str:
        from .pkce import get_pkce_token

        return get_pkce_token(
            client.host or "",
            self.provider,
            self.username,
            self.password.get_value(),
            secondary_password=self.secondary_password.get_value() if self.secondary_password else None,
            verify=client.verify,
            api_version=client.api_version,
        )

    def refresh(self, client: SafeguardClient) -> str:
        if not self.can_refresh:
            from .errors import SafeguardError

            raise SafeguardError("Cannot refresh PKCE connection that requires MFA. One-time passwords cannot be reused.")
        return self.authenticate(client)

    async def async_authenticate(self, client: AsyncSafeguardClient) -> str:
        from .async_pkce import async_get_pkce_token

        return await async_get_pkce_token(
            client.host or "",
            self.provider,
            self.username,
            self.password.get_value(),
            secondary_password=self.secondary_password.get_value() if self.secondary_password else None,
            verify=client.verify,
            api_version=client.api_version,
        )

    async def async_refresh(self, client: AsyncSafeguardClient) -> str:
        if not self.can_refresh:
            from .errors import SafeguardError

            raise SafeguardError("Cannot refresh PKCE connection that requires MFA. One-time passwords cannot be reused.")
        return await self.async_authenticate(client)

    def dispose(self) -> None:
        """Zero out sensitive fields."""
        self.password.dispose()
        if self.secondary_password is not None:
            self.secondary_password.dispose()


@dataclass(frozen=True, eq=False)
class TokenAuth:
    """Pre-existing bearer token authentication.

    This strategy has no refresh capability — when the token expires,
    a new one must be obtained externally.

    Example::

        auth = TokenAuth("existing-api-token")
        client = SafeguardClient("appliance", auth=auth)
    """

    token: HiddenString = field(repr=False)

    def __init__(self, token: str | HiddenString) -> None:
        object.__setattr__(self, "token", token if isinstance(token, HiddenString) else HiddenString(token))

    @property
    def can_refresh(self) -> bool:
        return False

    def authenticate(self, client: SafeguardClient) -> str:
        return self.token.get_value()

    def refresh(self, client: SafeguardClient) -> str:
        from .errors import SafeguardError

        raise SafeguardError("TokenAuth does not support refresh. Obtain a new token externally.")

    async def async_authenticate(self, client: AsyncSafeguardClient) -> str:
        return self.token.get_value()

    async def async_refresh(self, client: AsyncSafeguardClient) -> str:
        from .errors import SafeguardError

        raise SafeguardError("TokenAuth does not support refresh. Obtain a new token externally.")

    def dispose(self) -> None:
        """Zero out the stored token."""
        self.token.dispose()
