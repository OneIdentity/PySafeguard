"""Synchronous Safeguard API client.

The primary entry point for interacting with a One Identity Safeguard
appliance.

Example::

    from pysafeguard import SafeguardClient, PasswordAuth, Service

    with SafeguardClient("appliance.example.com", auth=PasswordAuth("local", "admin", "secret")) as client:
        resp = client.get(Service.CORE, "Users")
        users = resp.json()
"""

from __future__ import annotations

import json
import typing
from collections.abc import Mapping
from pathlib import Path
from types import TracebackType
from typing import IO, TYPE_CHECKING

from requests import Response, Session
from requests.structures import CaseInsensitiveDict

from .auth import Auth
from .data_types import HttpMethod, Service
from .errors import ApiError, SafeguardError
from .utility import JsonType, LiteralString, assemble_path, assemble_url

if TYPE_CHECKING:
    from .event import PersistentSafeguardEventListener, SafeguardEventListener

DEFAULT_TIMEOUT = 300
DEFAULT_STREAM_CHUNK_SIZE = 8192


class SafeguardClient:
    """Synchronous client for the One Identity Safeguard Web API.

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
        self._timeout = timeout
        self._session = Session()
        self._session.verify = verify
        self._headers = CaseInsensitiveDict({"accept": "application/json"})

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
        return f"SafeguardClient(host={self.host!r}, auth={auth_type}, {status})"

    # -- Lifecycle -----------------------------------------------------------

    def login(self) -> None:
        """Authenticate using the configured auth strategy.

        :raises SafeguardError: If no auth strategy is configured or
            authentication fails.
        """
        if self._auth is None:
            raise SafeguardError("No auth strategy configured. Pass an auth object to the constructor.")
        token = self._auth.authenticate(self)
        self._set_user_token(token)

    def logout(self) -> None:
        """Log out, invalidating the current token on the appliance.

        After logout, API calls will fail until :meth:`login` or
        :meth:`refresh_access_token` is called.
        """
        if self._user_token is None:
            return
        try:
            self.request(HttpMethod.POST, Service.CORE, "Token/Logout")
        except SafeguardError:
            pass  # Best-effort, matching SafeguardDotNet behavior
        self._set_user_token(None)

    def refresh_access_token(self) -> None:
        """Re-authenticate using the stored auth strategy to get a fresh token.

        :raises SafeguardError: If no auth strategy is configured or it
            does not support refresh.
        """
        if self._auth is None:
            raise SafeguardError("No auth strategy configured for token refresh.")
        if not self._auth.can_refresh:
            raise SafeguardError("The current auth strategy does not support token refresh.")
        token = self._auth.refresh(self)
        self._set_user_token(token)

    @property
    def token_lifetime_remaining(self) -> int | None:
        """Remaining token lifetime in minutes, or ``None`` if unavailable."""
        resp = self.request(HttpMethod.GET, Service.APPLIANCE, "SystemTime")
        remaining = resp.headers.get("x-tokenlifetimeremaining")
        if remaining is not None:
            return int(remaining, base=10)
        return None

    def close(self) -> None:
        """Close the underlying HTTP session and release resources."""
        self._session.close()

    def __enter__(self) -> SafeguardClient:
        if self._auth is not None:
            self.login()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        try:
            self.logout()
        except SafeguardError:
            pass
        self.close()

    # -- Provider lookup -----------------------------------------------------

    def get_provider_id(self, name: str) -> str:
        """Look up an authentication provider by name.

        :param name: The name of a configured provider.
        :returns: The rSTS provider ID string.
        :raises SafeguardError: If no provider matches.
        """
        resp = self.request(HttpMethod.GET, Service.CORE, "AuthenticationProviders")
        providers = resp.json()
        matches = [p for p in providers if name.upper() == typing.cast(str, p["Name"]).upper()]
        if not matches:
            raise SafeguardError(f"Unable to find Provider with Name {name!r} in\n{json.dumps(providers, indent=2, sort_keys=True)}")
        return typing.cast(str, matches[0]["RstsProviderId"])

    # -- HTTP verb methods ---------------------------------------------------

    def get(
        self,
        service: Service,
        endpoint: str | None = None,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        host: str | None = None,
        cert: tuple[str, str] | None = None,
        api_version: str | None = None,
    ) -> Response:
        """Send a GET request.

        :param service: The Safeguard service to call.
        :param endpoint: The API endpoint path (e.g. ``"Users"``).
        :returns: The :class:`~requests.Response`.
        """
        return self.request(HttpMethod.GET, service, endpoint, params=params, headers=headers, host=host, cert=cert, api_version=api_version)

    def post(
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
    ) -> Response:
        """Send a POST request.

        :param service: The Safeguard service to call.
        :param endpoint: The API endpoint path.
        :param json: JSON-serializable body (sets content-type automatically).
        :param data: Raw string body.
        :returns: The :class:`~requests.Response`.
        """
        return self.request(
            HttpMethod.POST, service, endpoint, json=json, data=data, params=params, headers=headers, host=host, cert=cert, api_version=api_version
        )

    def put(
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
    ) -> Response:
        """Send a PUT request.

        :param service: The Safeguard service to call.
        :param endpoint: The API endpoint path.
        :param json: JSON-serializable body (sets content-type automatically).
        :param data: Raw string body.
        :returns: The :class:`~requests.Response`.
        """
        return self.request(
            HttpMethod.PUT, service, endpoint, json=json, data=data, params=params, headers=headers, host=host, cert=cert, api_version=api_version
        )

    def delete(
        self,
        service: Service,
        endpoint: str | None = None,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        host: str | None = None,
        cert: tuple[str, str] | None = None,
        api_version: str | None = None,
    ) -> Response:
        """Send a DELETE request.

        :param service: The Safeguard service to call.
        :param endpoint: The API endpoint path.
        :returns: The :class:`~requests.Response`.
        """
        return self.request(HttpMethod.DELETE, service, endpoint, params=params, headers=headers, host=host, cert=cert, api_version=api_version)

    # -- Low-level request ---------------------------------------------------

    def request(
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
    ) -> Response:
        """Send a request to the Safeguard API.

        This is the low-level escape hatch that all verb methods delegate to.
        Use :meth:`get`, :meth:`post`, :meth:`put`, :meth:`delete` for
        convenience.

        :param method: HTTP method.
        :param service: The Safeguard service to target.
        :param endpoint: The API endpoint path (e.g. ``"Users"``).
        :param params: Query parameters.
        :param json: JSON-serializable request body.
        :param data: Raw string request body.
        :param headers: Additional headers (merged with defaults).
        :param host: Override host (useful for clusters).
        :param cert: Client certificate ``(cert_file, key_file)`` tuple.
        :param api_version: Override API version for this request.
        :returns: The :class:`~requests.Response`.
        """
        if self.auto_refresh and service not in (Service.RSTS, Service.APPLIANCE):
            self._check_and_refresh_token()

        url = assemble_url(
            host or self.host,
            assemble_path(
                service,
                (api_version or self.api_version) if service != Service.RSTS else "",
                endpoint,
            ),
            params or {},
        )
        merged = CaseInsensitiveDict(self._headers)
        if headers:
            merged.update(headers)
        return self._execute_web_request(method, url, json=json, data=data, headers=merged, cert=cert)

    # -- Streaming -----------------------------------------------------------

    def stream(
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
    ) -> Response:
        """Send a request with streaming enabled.

        Like :meth:`request`, but the response body is **not** read into
        memory. Use ``resp.iter_content()`` to consume it incrementally.
        The caller is responsible for closing the response.

        Example::

            resp = client.stream(HttpMethod.GET, Service.CORE, "Backups/Download")
            with resp:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
        """
        if self.auto_refresh and service not in (Service.RSTS, Service.APPLIANCE):
            self._check_and_refresh_token()

        url = assemble_url(
            host or self.host,
            assemble_path(
                service,
                (api_version or self.api_version) if service != Service.RSTS else "",
                endpoint,
            ),
            params or {},
        )
        merged = CaseInsensitiveDict(self._headers)
        if headers:
            merged.update(headers)
        return self._execute_web_request(method, url, json=json, data=data, headers=merged, cert=cert, stream=True)

    def download(
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
        resp = self.stream(HttpMethod.GET, service, endpoint, params=params, headers=headers, host=host, cert=cert, api_version=api_version)
        if resp.status_code != 200:
            resp.close()
            raise ApiError.from_response(resp)

        written = 0
        with resp, open(file_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=chunk_size):
                f.write(chunk)
                written += len(chunk)
        return written

    def upload(
        self,
        service: Service,
        endpoint: str,
        file_or_stream: str | Path | IO[bytes],
        *,
        content_type: str = "application/octet-stream",
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        host: str | None = None,
        cert: tuple[str, str] | None = None,
        api_version: str | None = None,
    ) -> Response:
        """Upload a file or stream to the Safeguard API.

        :param service: The Safeguard service to call.
        :param endpoint: The API endpoint path.
        :param file_or_stream: A file path or an open binary file-like object.
        :param content_type: MIME type (default ``"application/octet-stream"``).
        :returns: The :class:`~requests.Response`.
        """
        if self.auto_refresh and service not in (Service.RSTS, Service.APPLIANCE):
            self._check_and_refresh_token()

        url = assemble_url(
            host or self.host,
            assemble_path(
                service,
                (api_version or self.api_version) if service != Service.RSTS else "",
                endpoint,
            ),
            params or {},
        )
        merged = CaseInsensitiveDict(self._headers)
        if headers:
            merged.update(headers)
        merged["content-type"] = content_type

        if isinstance(file_or_stream, (str, Path)):
            with open(file_or_stream, "rb") as f:
                return self._session.request(HttpMethod.POST, url, headers=dict(merged), cert=cert, data=f, timeout=self._timeout)
        else:
            return self._session.request(HttpMethod.POST, url, headers=dict(merged), cert=cert, data=file_or_stream, timeout=self._timeout)

    # -- Event listeners -----------------------------------------------------

    def get_event_listener(self) -> SafeguardEventListener:
        """Create a :class:`~pysafeguard.event.SafeguardEventListener` using
        this client's current token.

        :raises SafeguardError: If the client has no user token.
        """
        from . import event

        if not self._user_token:
            raise SafeguardError("Client has no user token. Call login() before creating an event listener.")
        return event.SafeguardEventListener(self.host, self._user_token, self.verify)

    def get_persistent_event_listener(self) -> PersistentSafeguardEventListener:
        """Create a :class:`~pysafeguard.event.PersistentSafeguardEventListener`
        that re-authenticates on disconnect using the configured auth strategy.

        :raises SafeguardError: If no auth strategy is configured or it
            cannot refresh.
        """
        from . import event
        from .auth import CertificateAuth, PasswordAuth, PkceAuth

        auth = self._auth
        if auth is None:
            raise SafeguardError("No auth strategy configured for persistent event listener.")
        host = self.host
        verify = self.verify

        if isinstance(auth, PasswordAuth):
            return event.PersistentSafeguardEventListener.from_password(host, auth.username, auth.password.get_value(), auth.provider, verify)
        elif isinstance(auth, CertificateAuth):
            return event.PersistentSafeguardEventListener.from_certificate(host, auth.cert_file, auth.key_file, auth.provider, verify)
        elif isinstance(auth, PkceAuth):
            if not auth.can_refresh:
                raise SafeguardError("Cannot create persistent event listener for PKCE auth with MFA.")
            from .pkce import get_pkce_token

            def _pkce_token_factory() -> str:
                return get_pkce_token(host, auth.provider, auth.username, auth.password.get_value(), verify=verify)

            return event.PersistentSafeguardEventListener(host, _pkce_token_factory, verify)
        else:
            raise SafeguardError("Unsupported auth strategy for persistent event listener.")

    # -- Internal ------------------------------------------------------------

    def _set_user_token(self, token: str | None) -> None:
        """Set the user token and authorization header."""
        self._user_token = token
        if token:
            self._headers.update(authorization=f"Bearer {token}")
        else:
            self._headers.pop("authorization", None)

    def _check_and_refresh_token(self) -> None:
        """Check token lifetime and refresh if expired."""
        try:
            remaining = self.token_lifetime_remaining
            if remaining is None or remaining <= 0:
                self.refresh_access_token()
        except SafeguardError:
            self.refresh_access_token()

    def _execute_web_request(
        self,
        method: HttpMethod,
        url: str,
        *,
        json: JsonType | None = None,
        data: str | None = None,
        headers: Mapping[str, str],
        cert: tuple[str, str] | None = None,
        stream: bool = False,
    ) -> Response:
        """Execute the actual HTTP request via the session."""
        merged = CaseInsensitiveDict(headers)
        data_body: str | None = None
        json_body: JsonType | None = None

        if json is not None:
            json_body = json
            if not merged.get("content-type"):
                merged["content-type"] = "application/json"
        elif data is not None:
            data_body = data

        return self._session.request(method, url, headers=dict(merged), cert=cert, data=data_body, json=json_body, timeout=self._timeout, stream=stream)
