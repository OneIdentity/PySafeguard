# mypy: ignore-errors
# type: ignore

from .connection import Connection
from .connection import WebRequestError as WebRequestError
from .data_types import A2ATypes as A2ATypes
from .data_types import HttpMethods as HttpMethods
from .data_types import Services
from .data_types import SshKeyFormats as SshKeyFormats
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

        Arguments:
        conn -- PySafeguardConnection instance object
        callback -- Callback function to handle messages that come back
        username -- Username for authentication
        password -- Password for authentication
        """

        def _token_factory_username():
            conn.connect_password(username, password)
            return conn.UserToken

        options = {"access_token_factory": _token_factory_username}
        PySafeguardConnection.__register_signalr(conn.host, callback, options, bool(conn.req_globals.get("verify", True)))

    @staticmethod
    def register_signalr_certificate(conn, callback, certfile, keyfile):
        """Wrapper to register a SignalR callback using certificate authentication.

        Arguments:
        conn -- PySafeguardConnection instance object
        callback -- Callback function to handle messages that come back
        certfile -- Path to the user certificate in pem format.
        keyfile -- Path to the user certificate's key in key format.
        """

        def _token_factory_certificate():
            conn.connect_certificate(certfile, keyfile, provider="certificate")
            return conn.UserToken

        options = options = {"access_token_factory": _token_factory_certificate}
        PySafeguardConnection.__register_signalr(conn.host, callback, options, bool(conn.req_globals.get("verify", True)))
