import json
import ssl
import typing
from collections.abc import Mapping
from dataclasses import dataclass, field

from aiohttp import ClientResponse, ClientSession, ClientTimeout
from multidict import CIMultiDict
from truststore import SSLContext

from .data_types import A2ATypes, HttpMethods, Services, SshKeyFormats
from .exceptions import SafeguardException
from .hidden_string import HiddenString
from .utility import JsonType, LiteralString, assemble_path, assemble_url, get_access_token, get_user_token

DEFAULT_TIMEOUT = 300


# ---------------------------------------------------------------------------
# Auth credential storage (internal, async variants)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, eq=False)
class _AsyncPasswordCredential:
    username: str
    password: HiddenString = field(repr=False)
    provider: str

    def dispose(self) -> None:
        """Dispose sensitive fields."""
        self.password.dispose()


@dataclass(frozen=True, eq=False)
class _AsyncCertificateCredential:
    cert_file: str
    key_file: str
    provider: str


_AsyncAuthCredential = _AsyncPasswordCredential | _AsyncCertificateCredential


class AsyncWebRequestError(SafeguardException):
    """Exception raised for failed async HTTP responses from the Safeguard API."""

    def __init__(self, resp: ClientResponse) -> None:
        self.req = resp
        self.message = f"{resp.status} {resp.reason}: {resp.method} {resp.url}"
        super().__init__(self.message, status_code=resp.status)


class AsyncConnection:
    def __init__(self, host: str | None, verify: bool | str = True, apiVersion: LiteralString = "v4", *, timeout: int = DEFAULT_TIMEOUT) -> None:
        """
        Initialize an async Safeguard connection object.

        :param host: The appliance hostname.
        :param verify: A path to a file with CA certificate information or ``False`` to disable verification.
        :param apiVersion: The version of the API with which to connect.
        :param timeout: Request timeout in seconds. Defaults to 300.
        """

        self.host = host
        self.UserToken: str | None = None
        self.apiVersion = apiVersion
        self.verify = verify
        self.headers = CIMultiDict({"accept": "application/json"})
        self._timeout = ClientTimeout(total=timeout)
        self._session: ClientSession | None = None
        self._auth_credential: _AsyncAuthCredential | None = None
        self._auto_refresh = False

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

    async def close(self) -> None:
        """Close the underlying HTTP session and release resources."""
        if self._session is not None and not self._session.closed:
            await self._session.close()
            self._session = None

    async def __aenter__(self) -> "AsyncConnection":
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: object) -> None:
        await self.close()

    def _set_user_token(self, token: str | None) -> None:
        """Set the user token and authorization header (internal use only)."""
        self.UserToken = token
        if token:
            self.headers.update(authorization=f"Bearer {token}")
        else:
            self.headers.pop("authorization", None)

    def _replace_auth_credential(self, new_credential: _AsyncAuthCredential | None) -> None:
        """Swap stored auth credentials, disposing secrets from the old one."""
        old = self._auth_credential
        self._auth_credential = new_credential
        if old is not None and hasattr(old, "dispose"):
            old.dispose()

    async def _execute_web_request(
        self, httpMethod: HttpMethods, url: str, body: JsonType | str | None, headers: Mapping[str, str], cert: tuple[str, str] | None = None
    ) -> ClientResponse:
        data_body: str | None
        json_body: JsonType | None
        updated_headers = CIMultiDict(headers)
        if body and httpMethod in (HttpMethods.POST, HttpMethods.PUT) and not headers.get("content-type"):
            data_body = None
            json_body = body
            updated_headers["content-type"] = "application/json"
        else:
            if body is not None and not isinstance(body, str):
                raise TypeError("expected: body as a string")
            data_body = body
            json_body = None

        ssl_context = self._create_ssl_context(cert)
        session = await self._get_session()
        resp = await session.request(httpMethod, url, headers=updated_headers, ssl=ssl_context, data=data_body, json=json_body, timeout=self._timeout)
        await resp.read()
        return resp

    @classmethod
    async def a2a_get_credential(
        cls,
        host: str,
        apiKey: str,
        cert: str,
        key: str,
        verify: str | bool = True,
        a2aType: A2ATypes = A2ATypes.PASSWORD,
        keyFormat: SshKeyFormats = SshKeyFormats.OPENSSH,
        apiVersion: LiteralString = "v4",
    ) -> JsonType:
        """
        (Public) Retrieves an application to application credential.

        :param host: Name or ip of the safeguard appliance.
        :param apiKey: A2A api key.
        :param cert: Path to the user certificate in pem format.
        :param key: Path to the user certificate's key in key format.
        :param verify: A path to a file with CA certificate information or False to disable verification
        :param a2aType: Type of credential to retrieve (password, privatekey). Defaults to password.
        :param keyFormat: The privateKeyFormat to return (openssh, ssh2, putty). Defaults to openshh.
        :param apiVersion: API version to use. Defaults to v4.
        """

        if not apiKey:
            raise ValueError("apiKey may not be null or empty")

        if not cert and not key:
            raise ValueError("cert path and key path may not be null or empty")

        async with cls(host, verify=verify, apiVersion=apiVersion) as conn:
            query: dict[str, str] = {"type": a2aType}
            if a2aType == A2ATypes.PRIVATEKEY:
                query["keyFormat"] = keyFormat

            resp = await conn.invoke(
                HttpMethods.GET,
                Services.A2A,
                "Credentials",
                query=query,
                additionalHeaders={"authorization": f"A2A {apiKey}"},
                cert=(cert, key),
            )
            if resp.status != 200:
                raise AsyncWebRequestError(resp)
            return typing.cast(JsonType, await resp.json())

    async def get_provider_id(self, name: str) -> str:
        """
        Get an authentication provider by name to use when authenticating.

        :param name: The name of a configured provider.
        :returns: A string value which is the ID of a configured provider.
        """

        resp = await self.invoke(HttpMethods.GET, Services.CORE, "AuthenticationProviders")
        providers = await resp.json()
        matches = [provider for provider in providers if name.upper() == typing.cast(str, provider["Name"]).upper()]
        if not matches:
            raise SafeguardException("Unable to find Provider with Name {} in\n{}".format(name, json.dumps(providers, indent=2, sort_keys=True)))

        return typing.cast(str, matches[0]["RstsProviderId"])

    async def _connect(self, body: JsonType, cert: tuple[str, str] | None = None) -> None:
        resp = await self.invoke(HttpMethods.POST, Services.RSTS, "oauth2/token", body=body, cert=cert)
        if resp.status == 200 and "application/json" in resp.headers.get("content-type", ""):
            access_token = get_access_token(await resp.json())
            resp = await self.invoke(HttpMethods.POST, Services.CORE, "Token/LoginResponse", body=dict(StsAccessToken=access_token))
            if resp.status == 200 and "application/json" in resp.headers.get("content-type", ""):
                user_token = get_user_token(await resp.json())
                self._set_user_token(user_token)
            else:
                raise AsyncWebRequestError(resp)
        else:
            raise AsyncWebRequestError(resp)

    async def connect_password(self, username: str, password: str, provider: str = "local") -> None:
        """
        Obtain a token using username and password - used when connecting.

        :param username: The username of an authorized user.
        :param password: The password for the user.
        :param provider: An authentication provider ID associated with user.
        """

        body: JsonType = {
            "scope": f"rsts:sts:primaryproviderid:{provider}",
            "grant_type": "password",
            "username": username,
            "password": password,
        }
        await self._connect(body)
        self._replace_auth_credential(_AsyncPasswordCredential(username, HiddenString(password), provider))

    async def connect_certificate(self, certFile: str, keyFile: str, provider: str = "certificate") -> None:
        """
        Obtain a token using certificate and key file - used when connecting.

        :param certFile: Path to the client certificate.
        :param keyFile: Path to the key for the certificate.
        :param provider: An authentication provider ID associated with certificate.
        """

        body: JsonType = {
            "scope": f"rsts:sts:primaryproviderid:{provider}",
            "grant_type": "client_credentials",
        }
        await self._connect(body, cert=(certFile, keyFile))
        self._replace_auth_credential(_AsyncCertificateCredential(certFile, keyFile, provider))

    def connect_token(self, token: str | None) -> None:
        """
        Use an existing token. Clears any stored refresh credentials since
        a bare token cannot be refreshed.

        :param token: The user token.
        """

        self._replace_auth_credential(None)
        self._set_user_token(token)

    async def invoke(
        self,
        httpMethod: HttpMethods,
        httpService: Services,
        endpoint: str | None = None,
        query: Mapping[str, str] = {},
        body: JsonType | None = None,
        additionalHeaders: Mapping[str, str] = {},
        host: str | None = None,
        cert: tuple[str, str] | None = None,
        apiVersion: str | None = None,
    ) -> ClientResponse:
        """
        Invoke a web request against the Safeguard API.

        :param httpMethod: One of the predefined `HttpMethods`.
        :param httpService: One of the predefined `Services`.
        :param endpoint: The path of an API endpoint to use (e.g. 'Users', 'Assets').
        :param query: A dictionary of query parameters that are added to endpoint.
        :param body: The data that is sent in the request. Usually a dictionary.
        :param headers: Headers that are added to the request.
        :param host: The host to which the request is made (useful for clusters).
        :param cert: A 2-tuple of the certificate and key.
        :param apiVersion: Which version of the API to use in this request.
        :returns: Request `Response` object.
        """

        if self._auto_refresh and httpService not in (Services.RSTS, Services.APPLIANCE):
            await self._check_and_refresh_token()

        url = assemble_url(
            host or self.host or "",
            assemble_path(
                httpService,
                (apiVersion or self.apiVersion) if httpService != Services.RSTS else "",
                endpoint,
            ),
            query,
        )
        headers = CIMultiDict(self.headers)
        headers.update(additionalHeaders)
        return await self._execute_web_request(httpMethod, url, body, headers, cert=cert)

    async def _check_and_refresh_token(self) -> None:
        """Check token lifetime and refresh if expired. Used by auto-refresh."""
        try:
            remaining = await self.get_remaining_token_lifetime()
            if remaining is None or remaining <= 0:
                await self.refresh_access_token()
        except SafeguardException:
            await self.refresh_access_token()

    async def refresh_access_token(self) -> None:
        """Re-authenticate using the stored credentials to obtain a fresh token.

        :raises SafeguardException: If no refresh credentials are stored or
            if re-authentication fails.
        """
        cred = self._auth_credential
        if cred is None:
            raise SafeguardException(
                "No authentication credentials available for token refresh. Only password and certificate connections support async refresh."
            )

        if isinstance(cred, _AsyncPasswordCredential):
            body: JsonType = {
                "scope": f"rsts:sts:primaryproviderid:{cred.provider}",
                "grant_type": "password",
                "username": cred.username,
                "password": cred.password.get_value(),
            }
            await self._connect(body)
        elif isinstance(cred, _AsyncCertificateCredential):
            body = {
                "scope": f"rsts:sts:primaryproviderid:{cred.provider}",
                "grant_type": "client_credentials",
            }
            await self._connect(body, cert=(cred.cert_file, cred.key_file))

    async def logout(self) -> None:
        """Log out of the Safeguard appliance, invalidating the current token."""
        if self.UserToken is None:
            return
        try:
            await self.invoke(HttpMethods.POST, Services.CORE, "Token/Logout")
        except Exception:
            pass  # Best-effort
        self._set_user_token(None)

    async def get_remaining_token_lifetime(self) -> int | None:
        """
        Get the remaining time left on the access token.

        :returns: An integer value in minutes.
        """

        resp = await self.invoke(HttpMethods.GET, Services.APPLIANCE, "SystemTime")
        remaining = resp.headers.get("x-tokenlifetimeremaining")
        if remaining is not None:
            return int(remaining, base=10)
        else:
            return None
