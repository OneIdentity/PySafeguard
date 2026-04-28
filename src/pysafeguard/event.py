"""Safeguard event listener system using SignalR.

Provides two listener classes:

- :class:`SafeguardEventListener` — connects to the Safeguard SignalR hub
  and dispatches events to registered handlers by name.
- :class:`PersistentSafeguardEventListener` — wraps a listener with
  automatic reconnection and re-authentication on disconnect.

Both support context-manager usage and fluent handler registration::

    with SafeguardEventListener(host, token) as listener:
        listener.on("AssetCreated", handle_asset)
        listener.on("UserCreated", handle_user)
        listener.start()
        time.sleep(60)  # listen for events

Persistent listeners re-authenticate transparently on disconnect::

    with PersistentSafeguardEventListener.from_password(
        host, username, password
    ) as listener:
        listener.on("AssetCreated", handle_asset)
        listener.start()
        input("Press Enter to stop...")
"""

from __future__ import annotations

import enum
import json
import logging
import threading
from collections.abc import Callable
from typing import Any

from .data_types import Service
from .errors import SafeguardError
from .utility import assemble_path, assemble_url

logger = logging.getLogger(__name__)

SafeguardEventHandler = Callable[[str, str], None]
"""Callback signature for event handlers: ``(event_name, event_body) -> None``."""

SafeguardStateCallback = Callable[["EventListenerState"], None]
"""Callback signature for listener state changes."""


class EventListenerState(enum.Enum):
    """Connection states for a :class:`SafeguardEventListener`."""

    STARTING = "Starting"
    CONNECTED = "Connected"
    DISCONNECTED = "Disconnected"
    RECONNECTING = "Reconnecting"
    STOPPED = "Stopped"


# ---------------------------------------------------------------------------
# Event handler registry (internal)
# ---------------------------------------------------------------------------


class EventHandlerRegistry:
    """Routes SignalR events to handlers registered by event name.

    Event names are matched case-insensitively.  Each handler runs
    synchronously; exceptions are logged and swallowed so one bad
    handler cannot break the dispatch loop.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[SafeguardEventHandler]] = {}

    def register(self, event_name: str, handler: SafeguardEventHandler) -> None:
        """Register *handler* for *event_name*."""
        key = event_name.casefold()
        self._handlers.setdefault(key, []).append(handler)

    def handle_event(self, raw_event: str) -> None:
        """Parse a raw JSON event string and dispatch to registered handlers."""
        try:
            event = json.loads(raw_event)
        except (json.JSONDecodeError, TypeError):
            logger.warning("Could not parse event payload: %s", raw_event[:200])
            return

        if not isinstance(event, dict):
            logger.warning("Expected JSON object, got %s", type(event).__name__)
            return

        name: Any = event.get("Name", "")
        data: Any = event.get("Data", "")

        # A2A workaround: when Name is numeric, the real event name lives
        # inside Data.EventName (matches SafeguardDotNet behaviour).
        if isinstance(name, (int, float)) or (isinstance(name, str) and name.isdigit()):
            name = self._extract_event_name_from_data(data, fallback=str(name))

        name = str(name)
        body = json.dumps(data) if not isinstance(data, str) else data

        handlers = self._handlers.get(name.casefold(), [])
        for handler in handlers:
            try:
                handler(name, body)
            except Exception:
                logger.exception("Handler raised an exception for event '%s'", name)

    @property
    def registered_events(self) -> list[str]:
        """Return a list of registered event name keys (lower-cased)."""
        return list(self._handlers.keys())

    def copy(self) -> EventHandlerRegistry:
        """Return a shallow copy preserving all registrations."""
        new = EventHandlerRegistry()
        for key, handler_list in self._handlers.items():
            new._handlers[key] = list(handler_list)
        return new

    # ------------------------------------------------------------------

    @staticmethod
    def _extract_event_name_from_data(data: Any, *, fallback: str) -> str:
        """Pull ``EventName`` out of *data*, which may be a dict or JSON string."""
        if isinstance(data, dict):
            return str(data.get("EventName", fallback))
        if isinstance(data, str):
            try:
                parsed = json.loads(data)
                if isinstance(parsed, dict):
                    return str(parsed.get("EventName", fallback))
            except (json.JSONDecodeError, TypeError):
                pass
        return fallback


# ---------------------------------------------------------------------------
# Lazy import helper
# ---------------------------------------------------------------------------


def _import_hub_builder() -> Any:
    """Lazily import ``signalrcore`` with a helpful error on failure."""
    try:
        from signalrcore.hub_connection_builder import HubConnectionBuilder

        return HubConnectionBuilder
    except ImportError as exc:
        raise SafeguardError("SignalR support requires the 'signalr' extra. Install it with: pip install pysafeguard[signalr]") from exc


def _json_hub_protocol() -> Any:
    """Create a JsonHubProtocol with the correct version.

    signalrcore has a bug where it uses the negotiate response's
    ``negotiateVersion`` (which describes the negotiate *endpoint* protocol)
    as the SignalR hub protocol version.  Safeguard appliances return
    ``negotiateVersion: 0`` but require hub protocol version 1, causing
    a handshake failure: "The server does not support version 0 of the
    'json' protocol."

    By explicitly constructing the protocol with ``version=1`` and passing
    it via ``with_hub_protocol()``, we bypass the broken ProtocolFactory
    and get a successful handshake.
    """
    from signalrcore.protocol.json_hub_protocol import JsonHubProtocol

    return JsonHubProtocol(version=1)


# ---------------------------------------------------------------------------
# Standard event listener
# ---------------------------------------------------------------------------


class SafeguardEventListener:
    """Listen for Safeguard events over a SignalR connection.

    :param host: Appliance hostname or IP.
    :param access_token: A valid Safeguard user token.
    :param verify: TLS verification — ``True``, ``False``, or a CA bundle path.
    :param api_key: (A2A only) API key used as the Bearer token.

    The listener does **not** perform its own reconnection.  Use
    :class:`PersistentSafeguardEventListener` for automatic reconnection
    with re-authentication.
    """

    def __init__(
        self,
        host: str,
        access_token: str,
        verify: bool | str = True,
        *,
        api_key: str | None = None,
    ) -> None:
        self._host = host
        self._access_token = access_token
        self._verify = verify
        self._api_key = api_key

        self._registry = EventHandlerRegistry()
        self._state_callback: SafeguardStateCallback | None = None
        self._hub: Any = None
        self._started = False

    # -- fluent registration ------------------------------------------------

    def on(self, event_name: str, handler: SafeguardEventHandler) -> SafeguardEventListener:
        """Register *handler* for *event_name*.  Returns ``self`` for chaining."""
        self._registry.register(event_name, handler)
        return self

    def on_state_change(self, callback: SafeguardStateCallback) -> SafeguardEventListener:
        """Set a callback invoked when the connection state changes."""
        self._state_callback = callback
        return self

    # -- lifecycle -----------------------------------------------------------

    @property
    def is_started(self) -> bool:
        """``True`` if the listener is currently connected and receiving events."""
        return self._started

    def start(self) -> None:
        """Connect to the SignalR hub and begin receiving events.

        :raises SafeguardError: If signalrcore is not installed or the
            connection cannot be established.
        """
        if self._started:
            return

        HubConnectionBuilder = _import_hub_builder()

        event_url = assemble_url(self._host, assemble_path(Service.EVENT, "signalr"))

        verify_ssl = self._verify if isinstance(self._verify, bool) else True
        options: dict[str, Any] = {"verify_ssl": verify_ssl}

        if self._api_key:
            api_key = self._api_key
            options["access_token_factory"] = lambda: api_key
        else:
            token = self._access_token
            options["access_token_factory"] = lambda: token

        self._hub = HubConnectionBuilder().with_url(event_url, options=options).with_hub_protocol(_json_hub_protocol()).build()

        self._hub.on("NotifyEventAsync", self._on_signalr_event)
        self._hub.on("ReceiveMessage", self._on_signalr_event)
        self._hub.on_open(self._on_open)
        self._hub.on_close(self._on_close)
        self._hub.on_error(self._on_error)

        self._fire_state(EventListenerState.STARTING)
        self._hub.start()
        self._started = True
        self._fire_state(EventListenerState.CONNECTED)

    def stop(self) -> None:
        """Disconnect from the SignalR hub."""
        if not self._started and self._hub is None:
            return
        self._started = False
        if self._hub is not None:
            try:
                self._hub.stop()
            except Exception:
                logger.debug("Error stopping SignalR hub", exc_info=True)
            self._hub = None
        self._fire_state(EventListenerState.STOPPED)

    # -- context manager -----------------------------------------------------

    def __enter__(self) -> SafeguardEventListener:
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- internal callbacks --------------------------------------------------

    def _on_signalr_event(self, args: Any) -> None:
        """Normalise the raw SignalR callback payload and dispatch events."""
        if isinstance(args, list):
            for item in args:
                self._dispatch_item(item)
        elif isinstance(args, (dict, str)):
            self._dispatch_item(args)
        else:
            logger.warning("Unexpected SignalR event payload type: %s", type(args).__name__)

    def _dispatch_item(self, item: Any) -> None:
        """Dispatch a single event item through the registry."""
        if isinstance(item, dict):
            # Could be {Name, Data} directly or {Message: "<json>"}
            if "Name" in item:
                self._registry.handle_event(json.dumps(item))
            elif "Message" in item:
                self._registry.handle_event(str(item["Message"]))
            else:
                self._registry.handle_event(json.dumps(item))
        elif isinstance(item, str):
            self._registry.handle_event(item)
        else:
            self._registry.handle_event(json.dumps(item))

    def _on_open(self) -> None:
        logger.debug("SignalR connection opened to %s", self._host)

    def _on_close(self) -> None:
        logger.debug("SignalR connection closed for %s", self._host)
        if self._started:
            self._started = False
            self._fire_state(EventListenerState.DISCONNECTED)

    def _on_error(self, error: Any) -> None:
        logger.warning("SignalR error: %s", error)

    def _fire_state(self, state: EventListenerState) -> None:
        if self._state_callback is not None:
            try:
                self._state_callback(state)
            except Exception:
                logger.exception("State callback raised an exception")


# ---------------------------------------------------------------------------
# Persistent (auto-reconnecting) event listener
# ---------------------------------------------------------------------------


class PersistentSafeguardEventListener:
    """Auto-reconnecting event listener.

    On disconnect the listener re-authenticates using the supplied
    *token_factory* callable (which must return a fresh Safeguard user
    token) and reconnects automatically.  The reconnect loop retries
    every *retry_seconds* until :meth:`stop` is called.

    Convenience class methods are provided for common authentication
    modes:

    - :meth:`from_password` — username / password authentication
    - :meth:`from_certificate` — client certificate authentication

    :param host: Appliance hostname or IP.
    :param token_factory: A callable returning a fresh Safeguard user token.
    :param verify: TLS verification setting.
    :param retry_seconds: Seconds between reconnection attempts.
    """

    def __init__(
        self,
        host: str,
        token_factory: Callable[[], str],
        verify: bool | str = True,
        *,
        retry_seconds: float = 5.0,
    ) -> None:
        self._host = host
        self._token_factory = token_factory
        self._verify = verify
        self._retry_seconds = retry_seconds

        self._registry = EventHandlerRegistry()
        self._state_callback: SafeguardStateCallback | None = None
        self._listener: SafeguardEventListener | None = None
        self._started = False
        self._stop_event = threading.Event()
        self._reconnect_thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # -- factory class methods -----------------------------------------------

    @classmethod
    def from_password(
        cls,
        host: str,
        username: str,
        password: str,
        provider: str = "local",
        verify: bool | str = True,
        **kwargs: Any,
    ) -> PersistentSafeguardEventListener:
        """Create a persistent listener that re-authenticates with a password.

        :param host: Appliance hostname or IP.
        :param username: Safeguard username.
        :param password: Safeguard password.
        :param provider: Authentication provider (default ``"local"``).
        :param verify: TLS verification setting.
        :returns: A new :class:`PersistentSafeguardEventListener`.
        """
        from .auth import PasswordAuth
        from .client import SafeguardClient

        def token_factory() -> str:
            client = SafeguardClient(host, auth=PasswordAuth(provider, username, password), verify=verify)
            try:
                client.login()
                token = client.user_token
                if token is None:
                    raise SafeguardError("Authentication succeeded but no token was returned")
                return token
            finally:
                client.close()

        return cls(host, token_factory, verify, **kwargs)

    @classmethod
    def from_certificate(
        cls,
        host: str,
        cert_file: str,
        key_file: str,
        provider: str = "certificate",
        verify: bool | str = True,
        **kwargs: Any,
    ) -> PersistentSafeguardEventListener:
        """Create a persistent listener that re-authenticates with a client certificate.

        :param host: Appliance hostname or IP.
        :param cert_file: Path to the client certificate (PEM).
        :param key_file: Path to the certificate key.
        :param provider: Authentication provider (default ``"certificate"``).
        :param verify: TLS verification setting.
        :returns: A new :class:`PersistentSafeguardEventListener`.
        """
        from .auth import CertificateAuth
        from .client import SafeguardClient

        def token_factory() -> str:
            client = SafeguardClient(host, auth=CertificateAuth(cert_file, key_file, provider), verify=verify)
            try:
                client.login()
                token = client.user_token
                if token is None:
                    raise SafeguardError("Authentication succeeded but no token was returned")
                return token
            finally:
                client.close()

        return cls(host, token_factory, verify, **kwargs)

    # -- fluent registration ------------------------------------------------

    def on(self, event_name: str, handler: SafeguardEventHandler) -> PersistentSafeguardEventListener:
        """Register *handler* for *event_name*.  Returns ``self`` for chaining."""
        self._registry.register(event_name, handler)
        return self

    def on_state_change(self, callback: SafeguardStateCallback) -> PersistentSafeguardEventListener:
        """Set a callback invoked when the connection state changes."""
        self._state_callback = callback
        return self

    # -- lifecycle -----------------------------------------------------------

    @property
    def is_started(self) -> bool:
        """``True`` if the listener is active (connected or reconnecting)."""
        return self._started

    def start(self) -> None:
        """Start the listener and connect to the SignalR hub.

        On failure the listener enters a reconnect loop automatically.
        """
        if self._started:
            return
        self._started = True
        self._stop_event.clear()
        self._connect_inner()

    def stop(self) -> None:
        """Stop the listener and cancel any pending reconnection."""
        with self._lock:
            if not self._started:
                return
            self._started = False
            self._stop_event.set()

        thread = self._reconnect_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=self._retry_seconds + 2)
        self._reconnect_thread = None

        with self._lock:
            if self._listener is not None:
                self._listener.stop()
                self._listener = None

        self._fire_state(EventListenerState.STOPPED)

    # -- context manager -----------------------------------------------------

    def __enter__(self) -> PersistentSafeguardEventListener:
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- internal ------------------------------------------------------------

    def _connect_inner(self) -> None:
        """Create a fresh inner listener, authenticate, and start it."""
        try:
            token = self._token_factory()
            listener = SafeguardEventListener(self._host, token, self._verify)
            # Share our handler registry so registrations carry across reconnects.
            listener._registry = self._registry
            listener.on_state_change(self._inner_state_changed)
            listener.start()
            with self._lock:
                self._listener = listener
        except Exception:
            logger.exception("Failed to connect event listener")
            self._schedule_reconnect()

    def _inner_state_changed(self, state: EventListenerState) -> None:
        """Handle state changes from the inner listener."""
        if state == EventListenerState.DISCONNECTED and self._started:
            self._schedule_reconnect()
        else:
            self._fire_state(state)

    def _schedule_reconnect(self) -> None:
        """Start the background reconnect loop if not already running."""
        if self._stop_event.is_set():
            return
        self._fire_state(EventListenerState.RECONNECTING)
        with self._lock:
            if self._reconnect_thread is not None and self._reconnect_thread.is_alive():
                return  # already reconnecting
            self._reconnect_thread = threading.Thread(target=self._reconnect_loop, daemon=True, name="safeguard-event-reconnect")
            self._reconnect_thread.start()

    def _reconnect_loop(self) -> None:
        """Background loop: sleep → re-auth → reconnect → repeat on failure."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self._retry_seconds)
            if self._stop_event.is_set():
                break
            try:
                with self._lock:
                    if self._listener is not None:
                        self._listener.stop()
                        self._listener = None
                token = self._token_factory()
                listener = SafeguardEventListener(self._host, token, self._verify)
                listener._registry = self._registry
                listener.on_state_change(self._inner_state_changed)
                listener.start()
                with self._lock:
                    self._listener = listener
                logger.info("Reconnected event listener to %s", self._host)
                return
            except Exception:
                logger.exception("Reconnect attempt failed, retrying in %ss", self._retry_seconds)

    def _fire_state(self, state: EventListenerState) -> None:
        if self._state_callback is not None:
            try:
                self._state_callback(state)
            except Exception:
                logger.exception("State callback raised an exception")
