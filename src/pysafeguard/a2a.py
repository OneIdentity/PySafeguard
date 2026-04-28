"""Application-to-Application (A2A) context for Safeguard credential operations.

The :class:`A2AContext` provides a reusable wrapper around the Safeguard A2A
API surface.  It stores the client certificate and appliance address so they
don't need to be repeated on every call.  Each method takes an *api_key*
identifying the specific A2A registration to operate on.

**Authentication model**

A2A credential operations (retrieve/set password, private key, etc.) use
two-factor authentication in a single request:

- Client certificate on the TLS channel (proves identity).
- ``Authorization: A2A <api_key>`` header (authorises access to a specific
  account registration).

The :meth:`get_retrievable_accounts` method is different — it queries the
Core API and requires a user token obtained via certificate login.  This
authentication is performed lazily on first use.

Usage::

    with A2AContext("host", "cert.pem", "key.pem", verify=False) as a2a:
        password = a2a.retrieve_password(api_key)
        print(password.get_value())

    # or one-shot:
    password = A2AContext.quick_retrieve_password("host", api_key, "cert.pem", "key.pem")
"""

from __future__ import annotations

import typing
from typing import TYPE_CHECKING
from types import TracebackType

from .connection import Connection, WebRequestError
from .data_types import A2ATypes, HttpMethods, Services, SshKeyFormats
from .hidden_string import HiddenString
from .utility import JsonType, LiteralString

if TYPE_CHECKING:
    from .event import PersistentSafeguardEventListener, SafeguardEventListener


class A2AContext:
    """Reusable context for Safeguard A2A credential operations.

    :param host: Appliance hostname or IP address.
    :param cert_file: Path to the client certificate (PEM).
    :param key_file: Path to the certificate private key.
    :param verify: TLS verification — ``True``, ``False``, or a CA bundle path.
    :param api_version: API version (default ``"v4"``).
    """

    def __init__(
        self,
        host: str,
        cert_file: str,
        key_file: str,
        *,
        verify: bool | str = True,
        api_version: LiteralString = "v4",
    ) -> None:
        if not cert_file or not key_file:
            raise ValueError("cert_file and key_file are required for A2A context")

        self._host = host
        self._cert: tuple[str, str] = (cert_file, key_file)
        self._verify = verify
        self._api_version = api_version

        self._conn = Connection(host, verify=verify, apiVersion=api_version)
        self._user_authenticated = False

    # -- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        """Close the underlying connection and release resources."""
        self._conn.close()

    def __enter__(self) -> A2AContext:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- A2A credential operations (cert + api_key, no user token) ----------

    def retrieve_password(self, api_key: str) -> HiddenString:
        """Retrieve the password for the account bound to *api_key*.

        :param api_key: The A2A API key for the target account registration.
        :returns: The password wrapped in a :class:`~pysafeguard.HiddenString`.
        :raises SafeguardException: On authentication or API errors.
        """
        result = self._a2a_request(api_key, a2a_type=A2ATypes.PASSWORD)
        return HiddenString(str(result) if not isinstance(result, str) else result)

    def set_password(self, api_key: str, password: str) -> None:
        """Set or update the password for the account bound to *api_key*.

        :param api_key: The A2A API key for the target account registration.
        :param password: The new password value.
        """
        self._a2a_put(api_key, "Credentials/Password", body=password)

    def retrieve_private_key(
        self,
        api_key: str,
        *,
        key_format: SshKeyFormats = SshKeyFormats.OPENSSH,
    ) -> HiddenString:
        """Retrieve the SSH private key for the account bound to *api_key*.

        :param api_key: The A2A API key for the target account registration.
        :param key_format: Key format to return (default :attr:`SshKeyFormats.OPENSSH`).
        :returns: The private key wrapped in a :class:`~pysafeguard.HiddenString`.
        """
        result = self._a2a_request(api_key, a2a_type=A2ATypes.PRIVATEKEY, key_format=key_format)
        return HiddenString(str(result) if not isinstance(result, str) else result)

    def set_private_key(
        self,
        api_key: str,
        private_key: str,
        passphrase: str = "",
        *,
        key_format: SshKeyFormats = SshKeyFormats.OPENSSH,
    ) -> None:
        """Set or update the SSH key for the account bound to *api_key*.

        :param api_key: The A2A API key for the target account registration.
        :param private_key: The new private key value.
        :param passphrase: Optional passphrase protecting the key.
        :param key_format: Key format (default :attr:`SshKeyFormats.OPENSSH`).
        """
        body: JsonType = {
            "Passphrase": passphrase,
            "PrivateKey": private_key,
        }
        self._a2a_put(
            api_key,
            "Credentials/SshKey",
            body=body,
            query={"keyFormat": key_format},
        )

    def retrieve_api_key_secret(self, api_key: str) -> JsonType:
        """Retrieve API key secrets for the account bound to *api_key*.

        :param api_key: The A2A API key for the target account registration.
        :returns: A list of API key secret objects.
        """
        return self._a2a_request(api_key, a2a_type=A2ATypes.APIKEYSECRET)

    def broker_access_request(self, api_key: str, access_request: dict[str, JsonType]) -> str:
        """Submit a brokered access request through A2A.

        :param api_key: The A2A API key.
        :param access_request: The access request payload (dict).
        :returns: The access request ID as a string.
        """
        resp = self._conn.invoke(
            HttpMethods.POST,
            Services.A2A,
            "AccessRequests",
            body=access_request,
            additionalHeaders={"authorization": f"A2A {api_key}"},
            cert=self._cert,
        )
        if resp.status_code not in (200, 201):
            raise WebRequestError(resp)
        return str(resp.json())

    # -- Discovery (Core API, lazy user auth) --------------------------------

    def get_retrievable_accounts(self, *, filter: str | None = None) -> list[dict[str, JsonType]]:
        """List all A2A retrievable accounts across registrations.

        This method queries the Core API and requires user-level
        authentication.  The certificate login is performed lazily on
        first call.

        :param filter: Optional server-side OData filter expression.
        :returns: A list of retrievable account dicts, each decorated with
            ``ApplicationName``, ``Description``, and ``Disabled`` from the
            parent registration.
        """
        self._ensure_user_auth()

        resp = self._conn.invoke(HttpMethods.GET, Services.CORE, "A2ARegistrations")
        if resp.status_code != 200:
            raise WebRequestError(resp)
        registrations = resp.json()
        if not isinstance(registrations, list):
            return []

        accounts: list[dict[str, JsonType]] = []
        for reg in registrations:
            reg_id = reg.get("Id")
            if reg_id is None:
                continue

            query: dict[str, str] = {}
            if filter:
                query["filter"] = filter

            acct_resp = self._conn.invoke(
                HttpMethods.GET,
                Services.CORE,
                f"A2ARegistrations/{reg_id}/RetrievableAccounts",
                query=query,
            )
            if acct_resp.status_code != 200:
                continue

            acct_list = acct_resp.json()
            if not isinstance(acct_list, list):
                continue

            for acct in acct_list:
                if isinstance(acct, dict):
                    acct["ApplicationName"] = reg.get("AppName")
                    acct["Description"] = reg.get("Description")
                    acct["Disabled"] = acct.get("Disabled", False) or reg.get("Disabled", False)
                    accounts.append(acct)

        return accounts

    # -- Event listeners -----------------------------------------------------

    def get_event_listener(self, api_key: str) -> "SafeguardEventListener":
        """Create an A2A event listener using the API key for authentication.

        :param api_key: The A2A API key used as the access token for SignalR.
        :returns: A :class:`~pysafeguard.event.SafeguardEventListener`.

        .. note::
            The listener uses the API key as the SignalR access token.
            TLS client certificate authentication at the WebSocket transport
            level depends on the ``signalrcore`` library's SSL support.
        """
        from .event import SafeguardEventListener

        return SafeguardEventListener(self._host, api_key, self._verify, api_key=api_key)

    def get_persistent_event_listener(self, api_key: str) -> "PersistentSafeguardEventListener":
        """Create an auto-reconnecting A2A event listener.

        :param api_key: The A2A API key.
        :returns: A :class:`~pysafeguard.event.PersistentSafeguardEventListener`.
        """
        from .event import PersistentSafeguardEventListener

        return PersistentSafeguardEventListener(
            self._host,
            token_factory=lambda: api_key,
            verify=self._verify,
        )

    # -- Quick one-shot helpers (class methods) ------------------------------

    @classmethod
    def quick_retrieve_password(
        cls,
        host: str,
        api_key: str,
        cert_file: str,
        key_file: str,
        *,
        verify: bool | str = True,
        api_version: LiteralString = "v4",
    ) -> HiddenString:
        """One-shot password retrieval without creating a context.

        :param host: Appliance hostname or IP.
        :param api_key: The A2A API key.
        :param cert_file: Path to client certificate (PEM).
        :param key_file: Path to certificate key.
        :param verify: TLS verification setting.
        :param api_version: API version.
        :returns: The password wrapped in a :class:`~pysafeguard.HiddenString`.
        """
        with cls(host, cert_file, key_file, verify=verify, api_version=api_version) as ctx:
            return ctx.retrieve_password(api_key)

    @classmethod
    def quick_retrieve_private_key(
        cls,
        host: str,
        api_key: str,
        cert_file: str,
        key_file: str,
        *,
        key_format: SshKeyFormats = SshKeyFormats.OPENSSH,
        verify: bool | str = True,
        api_version: LiteralString = "v4",
    ) -> HiddenString:
        """One-shot private key retrieval without creating a context.

        :param host: Appliance hostname or IP.
        :param api_key: The A2A API key.
        :param cert_file: Path to client certificate (PEM).
        :param key_file: Path to certificate key.
        :param key_format: Key format (default :attr:`SshKeyFormats.OPENSSH`).
        :param verify: TLS verification setting.
        :param api_version: API version.
        :returns: The private key wrapped in a :class:`~pysafeguard.HiddenString`.
        """
        with cls(host, cert_file, key_file, verify=verify, api_version=api_version) as ctx:
            return ctx.retrieve_private_key(api_key, key_format=key_format)

    # -- Internal helpers ----------------------------------------------------

    def _ensure_user_auth(self) -> None:
        """Lazily authenticate as a user via certificate for Core API access."""
        if self._user_authenticated:
            return
        self._conn.connect_certificate(self._cert[0], self._cert[1])
        self._user_authenticated = True

    def _a2a_request(
        self,
        api_key: str,
        *,
        a2a_type: A2ATypes,
        key_format: SshKeyFormats = SshKeyFormats.OPENSSH,
    ) -> JsonType:
        """Execute a GET against the A2A Credentials endpoint."""
        if not api_key:
            raise ValueError("api_key must not be empty")

        query: dict[str, str] = {"type": a2a_type}
        if a2a_type == A2ATypes.PRIVATEKEY:
            query["keyFormat"] = key_format

        resp = self._conn.invoke(
            HttpMethods.GET,
            Services.A2A,
            "Credentials",
            query=query,
            additionalHeaders={"authorization": f"A2A {api_key}"},
            cert=self._cert,
        )
        if resp.status_code != 200:
            raise WebRequestError(resp)
        return typing.cast(JsonType, resp.json())

    def _a2a_put(
        self,
        api_key: str,
        endpoint: str,
        *,
        body: JsonType | str,
        query: dict[str, str] | None = None,
    ) -> None:
        """Execute a PUT against an A2A endpoint."""
        if not api_key:
            raise ValueError("api_key must not be empty")

        resp = self._conn.invoke(
            HttpMethods.PUT,
            Services.A2A,
            endpoint,
            query=query or {},
            body=body,
            additionalHeaders={"authorization": f"A2A {api_key}"},
            cert=self._cert,
        )
        if resp.status_code not in (200, 204):
            raise WebRequestError(resp)
