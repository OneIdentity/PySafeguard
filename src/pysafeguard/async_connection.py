import json
import ssl
import typing
from collections.abc import Mapping

from aiohttp import ClientResponse, ClientSession
from multidict import CIMultiDict
from truststore import SSLContext

from .data_types import A2ATypes, HttpMethods, JsonType, Services, SshKeyFormats
from .utility import LiteralString, assemble_path, assemble_url


class AsyncWebRequestError(Exception):
    def __init__(self, resp: ClientResponse) -> None:
        self.req = resp
        self.message = f"{resp.status} {resp.reason}: {resp.method} {resp.url}"
        super().__init__(self.message)


class AsyncConnection:
    host: str | None
    UserToken: str | None
    apiVersion: str
    verify: bool | str
    headers: CIMultiDict[str]

    def __init__(self, host: str | None, verify: bool | str = True, apiVersion: LiteralString = "v4") -> None:
        """
        Initialize a Safeguard connection object

        :param host: The appliance hostname.
        :param verify: A path to a file with CA certificate information or `False` to disable verification.
        :param apiVersion: The version of the API with which to connect.
        """

        self.host = host
        self.UserToken = None
        self.apiVersion = apiVersion
        self.verify = verify
        self.headers = CIMultiDict({"accept": "application/json"})

    @staticmethod
    async def __execute_web_request(
        httpMethod: HttpMethods, url: str, body: JsonType | str | None, headers: Mapping[str, str], verify: str | bool, cert: tuple[str, str] | None
    ) -> ClientResponse:
        data_body: str | None
        json_body: JsonType | None
        updated_headers = CIMultiDict(headers)
        if body and httpMethod in [HttpMethods.POST, HttpMethods.PUT] and not headers.get("content-type"):
            data_body = None
            if not isinstance(body, dict):
                raise TypeError("expected: body as a JSON object")
            json_body = body
            updated_headers["content-type"] = "application/json"
        else:
            if body is not None and not isinstance(body, str):
                raise TypeError("expected: body as a string")
            data_body = body
            json_body = None

        ctx = SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if cert is not None:
            certfile, keyfile = cert
            ctx.load_cert_chain(certfile, keyfile)
        elif isinstance(verify, str):
            ctx.load_cert_chain(verify)

        async with ClientSession() as session:
            async with session.request(httpMethod, url, headers=updated_headers, ssl=ctx, data=data_body, json=json_body) as resp:
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
            raise Exception("apiKey may not be null or empty")

        if not cert and not key:
            raise Exception("cert path and key path may not be null or empty")

        headers = CIMultiDict({"authorization": f"A2A {apiKey}"})
        query: dict[str, str] = {"type": a2aType}
        if a2aType == A2ATypes.PRIVATEKEY:
            query["keyFormat"] = keyFormat

        resp = await cls.__execute_web_request(
            HttpMethods.GET,
            assemble_url(host, assemble_path(Services.A2A, apiVersion, "Credentials"), query),
            body=None,
            headers=headers,
            verify=verify,
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
            raise Exception("Unable to find Provider with Name {} in\n{}".format(name, json.dumps(providers, indent=2, sort_keys=True)))

        return typing.cast(str, matches[0]["RstsProviderId"])

    async def __connect(self, body: JsonType, cert: tuple[str, str] | None = None) -> None:
        data: JsonType
        resp = await self.invoke(HttpMethods.POST, Services.RSTS, "oauth2/token", body=body, cert=cert)
        if resp.status == 200 and "application/json" in resp.headers.get("content-type", ""):
            data = await resp.json()
            if not isinstance(data, dict):
                raise TypeError("expected: JSON object with field `access_token`")
            access_token = data.get("access_token")

            resp = await self.invoke(HttpMethods.POST, Services.CORE, "Token/LoginResponse", body=dict(StsAccessToken=access_token))
            if resp.status == 200 and "application/json" in resp.headers.get("content-type", ""):
                data = await resp.json()
                if not isinstance(data, dict):
                    raise TypeError("expected: JSON object with field `UserToken`")
                user_token = typing.cast(str, data.get("UserToken"))
                self.connect_token(user_token)
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
        await self.__connect(body)

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
        await self.__connect(body, cert=(certFile, keyFile))

    def connect_token(self, token: str | None) -> None:
        """
        Use an existing token.

        :param token: The user token.
        """

        self.UserToken = token
        self.headers.update(authorization="Bearer {}".format(self.UserToken))

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
        return await self.__execute_web_request(httpMethod, url, body, headers, verify=self.verify, cert=cert)

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
