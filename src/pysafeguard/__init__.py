# mypy: ignore-errors
# type: ignore

import warnings

from .a2a import A2AContext as A2AContext
from .async_a2a import AsyncA2AContext as AsyncA2AContext
from .async_connection import AsyncConnection as AsyncConnection
from .async_pkce import async_connect_pkce as async_connect_pkce
from .async_pkce import async_get_pkce_token as async_get_pkce_token
from .connection import Connection
from .connection import WebRequestError as WebRequestError
from .data_types import A2ATypes as A2ATypes
from .data_types import HttpMethods as HttpMethods
from .data_types import Services
from .data_types import SshKeyFormats as SshKeyFormats
from .event import EventHandlerRegistry as EventHandlerRegistry
from .event import EventListenerState as EventListenerState
from .event import PersistentSafeguardEventListener as PersistentSafeguardEventListener
from .event import SafeguardEventHandler as SafeguardEventHandler
from .event import SafeguardEventListener as SafeguardEventListener
from .event import SafeguardStateCallback as SafeguardStateCallback
from .exceptions import SafeguardException as SafeguardException
from .hidden_string import HiddenString as HiddenString
from .pkce import connect_pkce as connect_pkce
from .pkce import get_pkce_token as get_pkce_token
from .utility import assemble_path, assemble_url


class PySafeguardConnection(Connection):
    @staticmethod
    def __register_signalr(host, callback, options, verify):
        """Register a SignalR callback and start listening."""
        from signalrcore.hub_connection_builder import HubConnectionBuilder

        if not callback:
            raise Exception("A callback must be specified to register for the SignalR events.")
        options.update({"verify_ssl": verify})
        server_url = assemble_url(host, assemble_path(Services.EVENT, "signalr"))
        hub_connection = (
            HubConnectionBuilder()
            .with_url(server_url, options=options)
            .with_automatic_reconnect({"type": "raw", "keep_alive_interval": 10, "reconnect_interval": 10, "max_attempts": 5})
            .build()
        )

        hub_connection.on("ReceiveMessage", callback)
        hub_connection.on("NotifyEventAsync", callback)
        hub_connection.on_open(lambda: print("connection opened and handshake received ready to send messages"))
        hub_connection.on_close(lambda: print("connection closed"))
        hub_connection.start()

    @staticmethod
    def register_signalr_username(conn, callback, username, password):
        """Wrapper to register a SignalR callback using username/password authentication.

        .. deprecated::
            Use :class:`~pysafeguard.event.SafeguardEventListener` or
            :meth:`Connection.get_event_listener` instead.

        Arguments:
        conn -- PySafeguardConnection instance object
        callback -- Callback function to handle messages that come back
        username -- Username for authentication
        password -- Password for authentication
        """
        warnings.warn(
            "register_signalr_username is deprecated. Use SafeguardEventListener or Connection.get_event_listener() instead.",
            DeprecationWarning,
            stacklevel=2,
        )

        def _token_factory_username():
            conn.connect_password(username, password)
            return conn.UserToken

        options = {"access_token_factory": _token_factory_username}
        PySafeguardConnection.__register_signalr(conn.host, callback, options, bool(conn.verify))

    @staticmethod
    def register_signalr_certificate(conn, callback, certfile, keyfile):
        """Wrapper to register a SignalR callback using certificate authentication.

        .. deprecated::
            Use :class:`~pysafeguard.event.SafeguardEventListener` or
            :meth:`Connection.get_event_listener` instead.

        Arguments:
        conn -- PySafeguardConnection instance object
        callback -- Callback function to handle messages that come back
        certfile -- Path to the user certificate in pem format.
        keyfile -- Path to the user certificate's key in key format.
        """
        warnings.warn(
            "register_signalr_certificate is deprecated. Use SafeguardEventListener or Connection.get_event_listener() instead.",
            DeprecationWarning,
            stacklevel=2,
        )

        def _token_factory_certificate():
            conn.connect_certificate(certfile, keyfile, provider="certificate")
            return conn.UserToken

        options = options = {"access_token_factory": _token_factory_certificate}
        PySafeguardConnection.__register_signalr(conn.host, callback, options, bool(conn.verify))


# ---------------------------------------------------------------------------
# Convenience factory functions
# ---------------------------------------------------------------------------


def connect_password(appliance, username, password, provider="local", verify=True, api_version="v4"):
    """Create an authenticated connection using username and password.

    :param appliance: Network address of the Safeguard appliance.
    :param username: Username for authentication.
    :param password: Password for authentication.
    :param provider: Authentication provider ID (default ``"local"``).
    :param verify: CA certificate path or ``False`` to disable TLS verification.
    :param api_version: API version (default ``"v4"``).
    :returns: An authenticated :class:`PySafeguardConnection`.

    .. note::
        Resource Owner Grant (ROG) is disabled by default on newer appliances.
        Use :func:`connect_pkce` instead if you receive a 400 error.
    """
    conn = PySafeguardConnection(appliance, verify, api_version)
    conn.connect_password(username, password, provider)
    return conn


def connect_certificate(appliance, cert_file, key_file, provider="certificate", verify=True, api_version="v4"):
    """Create an authenticated connection using a client certificate.

    :param appliance: Network address of the Safeguard appliance.
    :param cert_file: Path to the client certificate (PEM).
    :param key_file: Path to the certificate key.
    :param provider: Authentication provider ID (default ``"certificate"``).
    :param verify: CA certificate path or ``False`` to disable TLS verification.
    :param api_version: API version (default ``"v4"``).
    :returns: An authenticated :class:`PySafeguardConnection`.
    """
    conn = PySafeguardConnection(appliance, verify, api_version)
    conn.connect_certificate(cert_file, key_file, provider)
    return conn


def connect_token(appliance, token, verify=True, api_version="v4"):
    """Create a connection using an existing Safeguard API token.

    :param appliance: Network address of the Safeguard appliance.
    :param token: An existing Safeguard user token.
    :param verify: CA certificate path or ``False`` to disable TLS verification.
    :param api_version: API version (default ``"v4"``).
    :returns: An authenticated :class:`PySafeguardConnection`.
    """
    conn = PySafeguardConnection(appliance, verify, api_version)
    conn.connect_token(token)
    return conn


def connect_anonymous(appliance, verify=True, api_version="v4"):
    """Create an unauthenticated connection for anonymous API access.

    Only endpoints that do not require authentication (e.g. Notification/Status)
    are accessible with this connection.

    :param appliance: Network address of the Safeguard appliance.
    :param verify: CA certificate path or ``False`` to disable TLS verification.
    :param api_version: API version (default ``"v4"``).
    :returns: An unauthenticated :class:`PySafeguardConnection`.
    """
    return PySafeguardConnection(appliance, verify, api_version)


def connect_persistent(appliance, provider, username, password, secondary_password=None, verify=True, api_version="v4"):
    """Create a persistent PKCE connection that auto-refreshes its token.

    Combines :func:`connect_pkce` with automatic token refresh: before each
    API call the token lifetime is checked, and if expired a new token is
    obtained transparently.

    :param appliance: Network address of the Safeguard appliance.
    :param provider: Authentication provider name (e.g. ``"local"``).
    :param username: Username for authentication.
    :param password: Password for authentication.
    :param secondary_password: One-time password for MFA, or ``None``.
    :param verify: CA certificate path or ``False`` to disable TLS verification.
    :param api_version: API version (default ``"v4"``).
    :returns: An authenticated :class:`Connection` with auto-refresh enabled.

    .. note::
        PKCE connections that require MFA cannot be auto-refreshed because
        one-time passwords are not reusable. The initial connection will
        succeed, but :meth:`~Connection.refresh_access_token` will raise
        :class:`SafeguardException` when the token eventually expires.
    """
    conn = connect_pkce(appliance, provider, username, password, secondary_password, verify, api_version)
    conn._auto_refresh = True
    return conn


# ---------------------------------------------------------------------------
# Async convenience factory functions
# ---------------------------------------------------------------------------


async def async_connect_password(appliance, username, password, provider="local", verify=True, api_version="v4"):
    """Async: Create an authenticated connection using username and password.

    :param appliance: Network address of the Safeguard appliance.
    :param username: Username for authentication.
    :param password: Password for authentication.
    :param provider: Authentication provider ID (default ``"local"``).
    :param verify: CA certificate path or ``False`` to disable TLS verification.
    :param api_version: API version (default ``"v4"``).
    :returns: An authenticated :class:`AsyncConnection`.

    .. note::
        Resource Owner Grant (ROG) is disabled by default on newer appliances.
        Use :func:`async_connect_pkce` instead if you receive a 400 error.
    """
    conn = AsyncConnection(appliance, verify, api_version)
    await conn.connect_password(username, password, provider)
    return conn


async def async_connect_certificate(appliance, cert_file, key_file, provider="certificate", verify=True, api_version="v4"):
    """Async: Create an authenticated connection using a client certificate.

    :param appliance: Network address of the Safeguard appliance.
    :param cert_file: Path to the client certificate (PEM).
    :param key_file: Path to the certificate key.
    :param provider: Authentication provider ID (default ``"certificate"``).
    :param verify: CA certificate path or ``False`` to disable TLS verification.
    :param api_version: API version (default ``"v4"``).
    :returns: An authenticated :class:`AsyncConnection`.
    """
    conn = AsyncConnection(appliance, verify, api_version)
    await conn.connect_certificate(cert_file, key_file, provider)
    return conn


def async_connect_token(appliance, token, verify=True, api_version="v4"):
    """Async: Create a connection using an existing Safeguard API token.

    :param appliance: Network address of the Safeguard appliance.
    :param token: An existing Safeguard user token.
    :param verify: CA certificate path or ``False`` to disable TLS verification.
    :param api_version: API version (default ``"v4"``).
    :returns: An authenticated :class:`AsyncConnection`.
    """
    conn = AsyncConnection(appliance, verify, api_version)
    conn.connect_token(token)
    return conn


def async_connect_anonymous(appliance, verify=True, api_version="v4"):
    """Async: Create an unauthenticated connection for anonymous API access.

    :param appliance: Network address of the Safeguard appliance.
    :param verify: CA certificate path or ``False`` to disable TLS verification.
    :param api_version: API version (default ``"v4"``).
    :returns: An unauthenticated :class:`AsyncConnection`.
    """
    return AsyncConnection(appliance, verify, api_version)


async def async_connect_persistent(appliance, provider, username, password, secondary_password=None, verify=True, api_version="v4"):
    """Async: Create a persistent PKCE connection that auto-refreshes its token.

    :param appliance: Network address of the Safeguard appliance.
    :param provider: Authentication provider name (e.g. ``"local"``).
    :param username: Username for authentication.
    :param password: Password for authentication.
    :param secondary_password: One-time password for MFA, or ``None``.
    :param verify: CA certificate path or ``False`` to disable TLS verification.
    :param api_version: API version (default ``"v4"``).
    :returns: An authenticated :class:`AsyncConnection` with auto-refresh enabled.
    """
    conn = await async_connect_pkce(appliance, provider, username, password, secondary_password, verify, api_version)
    conn._auto_refresh = True
    return conn
