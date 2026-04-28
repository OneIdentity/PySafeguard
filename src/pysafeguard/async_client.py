"""Asynchronous Safeguard API client.

Async mirror of :class:`~pysafeguard.client.SafeguardClient` using
``aiohttp`` for non-blocking HTTP.

Example::

    from pysafeguard import AsyncSafeguardClient, PasswordAuth, Service

    async with AsyncSafeguardClient("appliance.example.com", auth=PasswordAuth("local", "admin", "secret")) as client:
        resp = await client.get(Service.CORE, "Users")
        users = await resp.json()
"""

from __future__ import annotations

import asyncio
import json
import ssl
import typing
from collections.abc import Mapping
from pathlib import Path

from aiohttp import ClientResponse, ClientSession, ClientTimeout
from multidict import CIMultiDict
from truststore import SSLContext

from .auth import Auth
from .data_types import HttpMethod, Service
from .errors import ApiError, SafeguardError
from .utility import JsonType, LiteralString, assemble_path, assemble_url

DEFAULT_TIMEOUT = 300
DEFAULT_STREAM_CHUNK_SIZE = 8192


class AsyncSafeguardClient:
    """Asynchronous client for the One Identity Safeguard Web API.

    :param host: The appliance hostname or IP address.
    :param auth: An authentication strategy (e.g. :class:`~pysafeguard.auth.PasswordAuth`).
        Pass ``None`` for anonymous/unauthenticated access.
    :param verify: A path to a CA certificate file, or ``False`` to disable
        TLS verification. Defaults to ``True``.
    :param api_version: API version string (default ``"v4"``).
    :param timeout: Request timeout in seconds (default 300).
    :param auto_refresh: If ``True``, automatically refresh the token before
        each request when the token has expired.
    """

    def __init__(
        self,
        host: str,
        auth: Auth | None = None,
        *,
        verify: bool | str = True,
        api_version: LiteralString = "v4",
        timeout: int = DEFAULT_TIMEOUT,
        auto_refresh: bool = False,
    ) -> None:
        self.host = host
        self.verify = verify
        self.api_version = api_version
        self.auto_refresh = auto_refresh

        self._auth = auth
        self._user_token: str | None = None
        self._timeout = ClientTimeout(total=timeout)
        self._session: ClientSession | None = None
        self._headers = CIMultiDict({"accept": "application/json"})

    # -- Properties ----------------------------------------------------------

    @property
    def user_token(self) -> str | None:
        """The current Safeguard user token, or ``None`` if not authenticated."""
        return self._user_token

    @property
    def is_authenticated(self) -> bool:
        """Whether the client currently holds a user token."""
        return self._user_token is not None

    # -- Repr ----------------------------------------------------------------

    def __repr__(self) -> str:
        auth_type = type(self._auth).__name__ if self._auth else "None"
        status = "authenticated" if self.is_authenticated else "not authenticated"
        return f"AsyncSafeguardClient(host={self.host!r}, auth={auth_type}, {status})"

    # -- Lifecycle -----------------------------------------------------------

    async def login(self) -> None:
        """Authenticate using the configured auth strategy.

        :raises SafeguardError: If no auth strategy is configured or
            authentication fails.
        """
        if self._auth is None:
            raise SafeguardError("No auth strategy configured. Pass an auth object to the constructor.")
        token = await self._auth.async_authenticate(self)
        self._set_user_token(token)

    async def logout(self) -> None:
        """Log out, invalidating the current token on the appliance."""
        if self._user_token is None:
            return
        try:
            await self.request(HttpMethod.POST, Service.CORE, "Token/Logout")
        except SafeguardError:
            pass  # Best-effort
        self._set_user_token(None)

    async def refresh_access_token(self) -> None:
        """Re-authenticate using the stored auth strategy to get a fresh token.

        :raises SafeguardError: If no auth strategy is configured or it
            does not support refresh.
        """
        if self._auth is None:
            raise SafeguardError("No auth strategy configured for token refresh.")
        if not self._auth.can_refresh:
            raise SafeguardError("The current auth strategy does not support token refresh.")
        token = await self._auth.async_refresh(self)
        self._set_user_token(token)

    async def get_token_lifetime_remaining(self) -> int | None:
        """Remaining token lifetime in minutes, or ``None`` if unavailable."""
        resp = await self.request(HttpMethod.GET, Service.APPLIANCE, "SystemTime")
        remaining = resp.headers.get("x-tokenlifetimeremaining")
        if remaining is not None:
            return int(remaining, base=10)
        return None

    async def close(self) -> None:
        """Close the underlying HTTP session and release resources."""
        if self._session is not None and not self._session.closed:
            await self._session.close()
            self._session = None

    async def __aenter__(self) -> AsyncSafeguardClient:
        if self._auth is not None:
            await self.login()
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: object) -> None:
        try:
            await self.logout()
        except SafeguardError:
            pass
        await self.close()

    # -- Provider lookup -----------------------------------------------------

    async def get_provider_id(self, name: str) -> str:
        """Look up an authentication provider by name.

        :param name: The name of a configured provider.
        :returns: The rSTS provider ID string.
        :raises SafeguardError: If no provider matches.
        """
        resp = await self.request(HttpMethod.GET, Service.CORE, "AuthenticationProviders")
        providers = await resp.json()
        matches = [p for p in providers if name.upper() == typing.cast(str, p["Name"]).upper()]
        if not matches:
            raise SafeguardError(f"Unable to find Provider with Name {name!r} in\n{json.dumps(providers, indent=2, sort_keys=True)}")
        return typing.cast(str, matches[0]["RstsProviderId"])

    # -- HTTP verb methods ---------------------------------------------------

    async def get(
        self,
        service: Service,
        endpoint: str | None = None,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        host: str | None = None,
        cert: tuple[str, str] | None = None,
        api_version: str | None = None,
    ) -> ClientResponse:
        """Send a GET request."""
        return await self.request(HttpMethod.GET, service, endpoint, params=params, headers=headers, host=host, cert=cert, api_version=api_version)

    async def post(
        self,
        service: Service,
        endpoint: str | None = None,
        *,
        json: JsonType | None = None,
        data: str | None = None,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        host: str | None = None,
        cert: tuple[str, str] | None = None,
        api_version: str | None = None,
    ) -> ClientResponse:
        """Send a POST request."""
        return await self.request(
            HttpMethod.POST, service, endpoint, json=json, data=data, params=params, headers=headers, host=host, cert=cert, api_version=api_version
        )

    async def put(
        self,
        service: Service,
        endpoint: str | None = None,
        *,
        json: JsonType | None = None,
        data: str | None = None,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        host: str | None = None,
        cert: tuple[str, str] | None = None,
        api_version: str | None = None,
    ) -> ClientResponse:
        """Send a PUT request."""
        return await self.request(
            HttpMethod.PUT, service, endpoint, json=json, data=data, params=params, headers=headers, host=host, cert=cert, api_version=api_version
        )

    async def delete(
        self,
        service: Service,
        endpoint: str | None = None,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        host: str | None = None,
        cert: tuple[str, str] | None = None,
        api_version: str | None = None,
    ) -> ClientResponse:
        """Send a DELETE request."""
        return await self.request(HttpMethod.DELETE, service, endpoint, params=params, headers=headers, host=host, cert=cert, api_version=api_version)

    # -- Low-level request ---------------------------------------------------

    async def request(
        self,
        method: HttpMethod,
        service: Service,
        endpoint: str | None = None,
        *,
        params: Mapping[str, str] | None = None,
        json: JsonType | None = None,
        data: str | None = None,
        headers: Mapping[str, str] | None = None,
        host: str | None = None,
        cert: tuple[str, str] | None = None,
        api_version: str | None = None,
    ) -> ClientResponse:
        """Send a request to the Safeguard API.

        This is the low-level escape hatch that all verb methods delegate to.

        :param method: HTTP method.
        :param service: The Safeguard service to target.
        :param endpoint: The API endpoint path.
        :param params: Query parameters.
        :param json: JSON-serializable request body.
        :param data: Raw string request body.
        :param headers: Additional headers (merged with defaults).
        :param host: Override host (useful for clusters).
        :param cert: Client certificate ``(cert_file, key_file)`` tuple.
        :param api_version: Override API version for this request.
        :returns: The :class:`~aiohttp.ClientResponse`.
        """
        if self.auto_refresh and service not in (Service.RSTS, Service.APPLIANCE):
            await self._check_and_refresh_token()

        url = assemble_url(
            host or self.host,
            assemble_path(
                service,
                (api_version or self.api_version) if service != Service.RSTS else "",
                endpoint,
            ),
            params or {},
        )
        merged = CIMultiDict(self._headers)
        if headers:
            merged.update(headers)
        return await self._execute_web_request(method, url, json=json, data=data, headers=merged, cert=cert)

    # -- Streaming -----------------------------------------------------------

    async def stream(
        self,
        method: HttpMethod,
        service: Service,
        endpoint: str | None = None,
        *,
        params: Mapping[str, str] | None = None,
        json: JsonType | None = None,
        data: str | None = None,
        headers: Mapping[str, str] | None = None,
        host: str | None = None,
        cert: tuple[str, str] | None = None,
        api_version: str | None = None,
    ) -> ClientResponse:
        """Send a request with streaming enabled.

        Like :meth:`request`, but the response body is **not** eagerly
        read into memory. Use ``resp.content.iter_chunked()`` to consume
        the body incrementally. The caller is responsible for releasing
        the response.
        """
        if self.auto_refresh and service not in (Service.RSTS, Service.APPLIANCE):
            await self._check_and_refresh_token()

        url = assemble_url(
            host or self.host,
            assemble_path(
                service,
                (api_version or self.api_version) if service != Service.RSTS else "",
                endpoint,
            ),
            params or {},
        )
        merged = CIMultiDict(self._headers)
        if headers:
            merged.update(headers)
        return await self._execute_web_request(method, url, json=json, data=data, headers=merged, cert=cert, read_body=False)

    async def download(
        self,
        service: Service,
        endpoint: str,
        file_path: str | Path,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        host: str | None = None,
        cert: tuple[str, str] | None = None,
        api_version: str | None = None,
        chunk_size: int = DEFAULT_STREAM_CHUNK_SIZE,
    ) -> int:
        """Download a response body to a file.

        :param service: The Safeguard service to call.
        :param endpoint: The API endpoint path.
        :param file_path: Destination file path (will be created/overwritten).
        :param chunk_size: Size of each streamed chunk in bytes (default 8192).
        :returns: The number of bytes written.
        """
        resp = await self.stream(HttpMethod.GET, service, endpoint, params=params, headers=headers, host=host, cert=cert, api_version=api_version)
        if resp.status != 200:
            await resp.read()
            raise ApiError.from_async_response(resp, await resp.text())

        written = 0
        f = await asyncio.to_thread(open, file_path, "wb")
        try:
            async for chunk in resp.content.iter_chunked(chunk_size):
                await asyncio.to_thread(f.write, chunk)
                written += len(chunk)
        finally:
            await asyncio.to_thread(f.close)
            resp.release()
        return written

    async def upload(
        self,
        service: Service,
        endpoint: str,
        file_or_stream: str | Path | bytes | typing.IO[bytes],
        *,
        content_type: str = "application/octet-stream",
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        host: str | None = None,
        cert: tuple[str, str] | None = None,
        api_version: str | None = None,
    ) -> ClientResponse:
        """Upload a file or bytes to the Safeguard API.

        :param service: The Safeguard service to call.
        :param endpoint: The API endpoint path.
        :param file_or_stream: A file path, raw ``bytes``, or an open binary
            file-like object (e.g. ``io.BytesIO``).
        :param content_type: MIME type (default ``"application/octet-stream"``).
        :returns: The :class:`~aiohttp.ClientResponse`.
        """
        if self.auto_refresh and service not in (Service.RSTS, Service.APPLIANCE):
            await self._check_and_refresh_token()

        url = assemble_url(
            host or self.host,
            assemble_path(
                service,
                (api_version or self.api_version) if service != Service.RSTS else "",
                endpoint,
            ),
            params or {},
        )
        merged = CIMultiDict(self._headers)
        if headers:
            merged.update(headers)
        merged["content-type"] = content_type

        if isinstance(file_or_stream, (str, Path)):
            with open(file_or_stream, "rb") as f:
                upload_data = f.read()
        elif isinstance(file_or_stream, bytes):
            upload_data = file_or_stream
        else:
            # file-like object (IO[bytes])
            upload_data = file_or_stream.read()

        ssl_context = self._create_ssl_context(cert)
        session = await self._get_session()
        resp = await session.request(HttpMethod.POST, url, headers=merged, ssl=ssl_context, data=upload_data, timeout=self._timeout)
        await resp.read()
        return resp

    # -- Internal ------------------------------------------------------------

    def _set_user_token(self, token: str | None) -> None:
        """Set the user token and authorization header."""
        self._user_token = token
        if token:
            self._headers.update(authorization=f"Bearer {token}")
        else:
            self._headers.pop("authorization", None)

    async def _check_and_refresh_token(self) -> None:
        """Check token lifetime and refresh if expired."""
        try:
            remaining = await self.get_token_lifetime_remaining()
            if remaining is None or remaining <= 0:
                await self.refresh_access_token()
        except SafeguardError:
            await self.refresh_access_token()

    def _create_ssl_context(self, cert: tuple[str, str] | None = None) -> ssl.SSLContext | bool:
        """Build an SSL context based on verification and client certificate settings."""
        if self.verify is False and cert is None:
            return False

        ctx = SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if isinstance(self.verify, str):
            ctx.load_verify_locations(self.verify)
        elif self.verify is False:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if cert is not None:
            ctx.load_cert_chain(cert[0], cert[1])
        return ctx

    async def _get_session(self) -> ClientSession:
        """Return the persistent session, creating it lazily if needed."""
        if self._session is None or self._session.closed:
            self._session = ClientSession()
        return self._session

    async def _execute_web_request(
        self,
        method: HttpMethod,
        url: str,
        *,
        json: JsonType | None = None,
        data: str | None = None,
        headers: Mapping[str, str],
        cert: tuple[str, str] | None = None,
        read_body: bool = True,
    ) -> ClientResponse:
        """Execute the actual HTTP request via the session."""
        merged = CIMultiDict(headers)
        data_body: str | None = None
        json_body: JsonType | None = None

        if json is not None:
            json_body = json
            if not merged.get("content-type"):
                merged["content-type"] = "application/json"
        elif data is not None:
            data_body = data

        ssl_context = self._create_ssl_context(cert)
        session = await self._get_session()
        resp = await session.request(method, url, headers=merged, ssl=ssl_context, data=data_body, json=json_body, timeout=self._timeout)
        if read_body:
            await resp.read()
        return resp
