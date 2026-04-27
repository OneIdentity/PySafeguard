import json
import typing
from collections.abc import Mapping
from types import TracebackType

from requests import Response, Session
from requests.structures import CaseInsensitiveDict

from .data_types import A2ATypes, HttpMethods, Services, SshKeyFormats
from .exceptions import SafeguardException
from .utility import JsonType, LiteralString, assemble_path, assemble_url, get_access_token, get_user_token

DEFAULT_TIMEOUT = 300


class WebRequestError(SafeguardException):
    """Exception raised for failed HTTP responses from the Safeguard API."""

    def __init__(self, resp: Response) -> None:
        self.req = resp
        self.message = f"{resp.status_code} {resp.reason}: {resp.request.method} {resp.url}\n{resp.text}"
        super().__init__(self.message, status_code=resp.status_code, response=resp.text)


class Connection:
    host: str | None
    UserToken: str | None
    apiVersion: str
    verify: bool | str
    headers: CaseInsensitiveDict[str]

    def __init__(self, host: str | None, verify: bool | str = True, apiVersion: LiteralString = "v4", *, timeout: int = DEFAULT_TIMEOUT) -> None:
        """
        Initialize a Safeguard connection object.

        :param host: The appliance hostname.
        :param verify: A path to a file with CA certificate information or ``False`` to disable verification.
        :param apiVersion: The version of the API with which to connect.
        :param timeout: Request timeout in seconds. Defaults to 300.
        """

        self.host = host
        self.UserToken = None
        self.apiVersion = apiVersion
        self.verify = verify
        self.headers = CaseInsensitiveDict({"accept": "application/json"})
        self._timeout = timeout
        self._session = Session()
        self._session.verify = verify

    def close(self) -> None:
        """Close the underlying HTTP session and release resources."""
        self._session.close()

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        self.close()

    def _execute_web_request(
        self, httpMethod: HttpMethods, url: str, body: JsonType | str | None, headers: Mapping[str, str], cert: tuple[str, str] | None = None
    ) -> Response:
        data_body: str | None
        json_body: JsonType | None
        updated_headers = CaseInsensitiveDict(headers)
        if body and httpMethod in (HttpMethods.POST, HttpMethods.PUT) and not headers.get("content-type"):
            data_body = None
            json_body = body
            updated_headers["content-type"] = "application/json"
        else:
            if body is not None and not isinstance(body, str):
                raise TypeError("expected: body as a string")
            data_body = body
            json_body = None

        return self._session.request(httpMethod, url, headers=dict(updated_headers), cert=cert, data=data_body, json=json_body, timeout=self._timeout)

    @classmethod
    def a2a_get_credential(
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

        with cls(host, verify=verify, apiVersion=apiVersion) as conn:
            query: dict[str, str] = {"type": a2aType}
            if a2aType == A2ATypes.PRIVATEKEY:
                query["keyFormat"] = keyFormat

            resp = conn.invoke(
                HttpMethods.GET,
                Services.A2A,
                "Credentials",
                query=query,
                additionalHeaders={"authorization": f"A2A {apiKey}"},
                cert=(cert, key),
            )
            if resp.status_code != 200:
                raise WebRequestError(resp)
            return typing.cast(JsonType, resp.json())

    def get_provider_id(self, name: str) -> str:
        """
        Get an authentication provider by name to use when authenticating.

        :param name: The name of a configured provider.
        :returns: A string value which is the ID of a configured provider.
        """

        resp = self.invoke(HttpMethods.GET, Services.CORE, "AuthenticationProviders")
        providers = resp.json()
        matches = [provider for provider in providers if name.upper() == typing.cast(str, provider["Name"]).upper()]
        if not matches:
            raise SafeguardException("Unable to find Provider with Name {} in\n{}".format(name, json.dumps(providers, indent=2, sort_keys=True)))

        return typing.cast(str, matches[0]["RstsProviderId"])

    def _connect(self, body: JsonType, cert: tuple[str, str] | None = None) -> None:
        resp = self.invoke(HttpMethods.POST, Services.RSTS, "oauth2/token", body=body, cert=cert)
        if resp.status_code == 200 and "application/json" in resp.headers.get("content-type", ""):
            access_token = get_access_token(resp.json())
            resp = self.invoke(HttpMethods.POST, Services.CORE, "Token/LoginResponse", body=dict(StsAccessToken=access_token))
            if resp.status_code == 200 and "application/json" in resp.headers.get("content-type", ""):
                user_token = get_user_token(resp.json())
                self.connect_token(user_token)
            else:
                raise WebRequestError(resp)
        else:
            raise WebRequestError(resp)

    def connect_password(self, username: str, password: str, provider: str = "local") -> None:
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
        self._connect(body)

    def connect_certificate(self, certFile: str, keyFile: str, provider: str = "certificate") -> None:
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
        self._connect(body, cert=(certFile, keyFile))

    def connect_token(self, token: str | None) -> None:
        """
        Use an existing token.

        :param token: The user token.
        """

        self.UserToken = token
        self.headers.update(authorization="Bearer {}".format(self.UserToken))

    def invoke(
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
    ) -> Response:
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

        url = assemble_url(
            host or self.host or "",
            assemble_path(
                httpService,
                (apiVersion or self.apiVersion) if httpService != Services.RSTS else "",
                endpoint,
            ),
            query,
        )
        headers = CaseInsensitiveDict(self.headers)
        headers.update(additionalHeaders)
        return self._execute_web_request(httpMethod, url, body, headers, cert=cert)

    def get_remaining_token_lifetime(self) -> int | None:
        """
        Get the remaining time left on the access token.

        :returns: An integer value in minutes.
        """

        resp = self.invoke(HttpMethods.GET, Services.APPLIANCE, "SystemTime")
        remaining = resp.headers.get("x-tokenlifetimeremaining")
        if remaining is not None:
            return int(remaining, base=10)
        else:
            return None
