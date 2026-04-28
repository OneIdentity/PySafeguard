"""Tests for the event handler registry, listener construction, and state management.

These are pure-logic tests that do not require signalrcore or a live appliance.
"""

import json
import warnings

import pytest

from pysafeguard.event import EventHandlerRegistry, EventListenerState, PersistentSafeguardEventListener, SafeguardEventListener
from pysafeguard.exceptions import SafeguardException


# ---------------------------------------------------------------------------
# EventHandlerRegistry
# ---------------------------------------------------------------------------


class TestEventHandlerRegistry:
    def test_register_and_dispatch(self):
        registry = EventHandlerRegistry()
        received = []
        registry.register("AssetCreated", lambda name, body: received.append((name, body)))

        registry.handle_event(json.dumps({"Name": "AssetCreated", "Data": {"Id": 42}}))

        assert len(received) == 1
        assert received[0][0] == "AssetCreated"
        assert json.loads(received[0][1])["Id"] == 42

    def test_case_insensitive_dispatch(self):
        registry = EventHandlerRegistry()
        received = []
        registry.register("assetcreated", lambda name, body: received.append(name))

        registry.handle_event(json.dumps({"Name": "AssetCreated", "Data": "test"}))
        assert len(received) == 1

    def test_multiple_handlers_per_event(self):
        registry = EventHandlerRegistry()
        counts = {"a": 0, "b": 0}
        registry.register("Foo", lambda n, b: counts.__setitem__("a", counts["a"] + 1))
        registry.register("Foo", lambda n, b: counts.__setitem__("b", counts["b"] + 1))

        registry.handle_event(json.dumps({"Name": "Foo", "Data": ""}))
        assert counts == {"a": 1, "b": 1}

    def test_unregistered_event_is_ignored(self):
        """Events with no registered handlers are silently dropped."""
        registry = EventHandlerRegistry()
        registry.handle_event(json.dumps({"Name": "NobodyListening", "Data": ""}))

    def test_invalid_json_is_ignored(self):
        """Malformed JSON is logged but does not raise."""
        registry = EventHandlerRegistry()
        registry.handle_event("not valid json {{{")

    def test_non_object_json_is_ignored(self):
        """JSON arrays or primitives are logged but not dispatched."""
        registry = EventHandlerRegistry()
        registry.handle_event(json.dumps([1, 2, 3]))

    def test_handler_exception_does_not_break_dispatch(self):
        """If one handler raises, subsequent handlers still run."""
        registry = EventHandlerRegistry()
        received = []

        def bad_handler(name, body):
            raise ValueError("boom")

        def good_handler(name, body):
            received.append(name)

        registry.register("Evt", bad_handler)
        registry.register("Evt", good_handler)

        registry.handle_event(json.dumps({"Name": "Evt", "Data": ""}))
        assert len(received) == 1

    def test_a2a_numeric_name_workaround_dict_data(self):
        """When Name is numeric, EventName is extracted from Data dict."""
        registry = EventHandlerRegistry()
        received = []
        registry.register("AssetAccountPasswordUpdated", lambda name, body: received.append(name))

        event = {"Name": 123, "Data": {"EventName": "AssetAccountPasswordUpdated", "AccountId": 7}}
        registry.handle_event(json.dumps(event))

        assert len(received) == 1
        assert received[0] == "AssetAccountPasswordUpdated"

    def test_a2a_numeric_name_workaround_string_data(self):
        """When Name is numeric, EventName is extracted from JSON string Data."""
        registry = EventHandlerRegistry()
        received = []
        registry.register("AssetAccountPasswordUpdated", lambda name, body: received.append(name))

        inner = json.dumps({"EventName": "AssetAccountPasswordUpdated", "AccountId": 7})
        event = {"Name": "123", "Data": inner}
        registry.handle_event(json.dumps(event))

        assert len(received) == 1

    def test_data_passed_as_string(self):
        """When Data is already a string, it's passed through as-is."""
        registry = EventHandlerRegistry()
        received = []
        registry.register("Evt", lambda name, body: received.append(body))

        registry.handle_event(json.dumps({"Name": "Evt", "Data": "raw string data"}))
        assert received[0] == "raw string data"

    def test_data_passed_as_dict_is_serialized(self):
        """When Data is a dict, it's serialized to JSON for the handler."""
        registry = EventHandlerRegistry()
        received = []
        registry.register("Evt", lambda name, body: received.append(body))

        registry.handle_event(json.dumps({"Name": "Evt", "Data": {"key": "val"}}))
        assert json.loads(received[0]) == {"key": "val"}

    def test_registered_events_property(self):
        registry = EventHandlerRegistry()
        registry.register("Alpha", lambda n, b: None)
        registry.register("Beta", lambda n, b: None)

        events = registry.registered_events
        assert "alpha" in events
        assert "beta" in events

    def test_copy_preserves_handlers(self):
        registry = EventHandlerRegistry()
        received = []
        registry.register("Evt", lambda name, body: received.append(name))

        copy = registry.copy()
        copy.handle_event(json.dumps({"Name": "Evt", "Data": ""}))
        assert len(received) == 1

    def test_copy_is_independent(self):
        """Registering on a copy does not affect the original."""
        registry = EventHandlerRegistry()
        copy = registry.copy()
        copy.register("NewEvt", lambda n, b: None)

        assert "newevt" not in registry.registered_events


# ---------------------------------------------------------------------------
# EventListenerState
# ---------------------------------------------------------------------------


class TestEventListenerState:
    def test_all_states_exist(self):
        assert EventListenerState.STARTING.value == "Starting"
        assert EventListenerState.CONNECTED.value == "Connected"
        assert EventListenerState.DISCONNECTED.value == "Disconnected"
        assert EventListenerState.RECONNECTING.value == "Reconnecting"
        assert EventListenerState.STOPPED.value == "Stopped"


# ---------------------------------------------------------------------------
# SafeguardEventListener (construction and interface, no signalr)
# ---------------------------------------------------------------------------


class TestSafeguardEventListener:
    def test_construction(self):
        listener = SafeguardEventListener("myhost", "mytoken")
        assert listener._host == "myhost"
        assert listener._access_token == "mytoken"
        assert listener.is_started is False

    def test_fluent_on_registration(self):
        """`.on()` returns self for chaining."""
        listener = SafeguardEventListener("h", "t")
        result = listener.on("Evt", lambda n, b: None).on("Evt2", lambda n, b: None)
        assert result is listener
        assert "evt" in listener._registry.registered_events
        assert "evt2" in listener._registry.registered_events

    def test_fluent_on_state_change(self):
        """`.on_state_change()` returns self for chaining."""
        listener = SafeguardEventListener("h", "t")
        result = listener.on_state_change(lambda s: None)
        assert result is listener
        assert listener._state_callback is not None

    def test_start_without_signalrcore_raises(self):
        """start() gives a clear error if signalrcore is not installed."""
        # signalrcore IS installed in our venv, so we mock the import
        import pysafeguard.event as event_mod
        from unittest.mock import patch

        def fake_import():
            raise SafeguardException("SignalR support requires the 'signalr' extra.")

        listener = SafeguardEventListener("h", "t")
        with patch.object(event_mod, "_import_hub_builder", side_effect=fake_import):
            with pytest.raises(SafeguardException, match="signalr"):
                listener.start()

    def test_context_manager_calls_stop(self):
        """Exiting the context manager stops the listener."""
        listener = SafeguardEventListener("h", "t")
        listener._started = True
        with listener:
            assert listener.is_started
        assert not listener.is_started

    def test_stop_when_not_started_is_noop(self):
        """Calling stop() when not started does nothing."""
        listener = SafeguardEventListener("h", "t")
        listener.stop()
        assert not listener.is_started

    def test_dispatch_item_dict_with_name(self):
        """Direct dispatch of a {Name, Data} dict."""
        listener = SafeguardEventListener("h", "t")
        received = []
        listener.on("AssetCreated", lambda n, b: received.append(n))
        listener._dispatch_item({"Name": "AssetCreated", "Data": {"Id": 1}})
        assert received == ["AssetCreated"]

    def test_dispatch_item_dict_with_message(self):
        """Legacy dispatch of a {Message: "<json>"} dict."""
        listener = SafeguardEventListener("h", "t")
        received = []
        listener.on("AssetCreated", lambda n, b: received.append(n))
        inner_json = json.dumps({"Name": "AssetCreated", "Data": {}})
        listener._dispatch_item({"Message": inner_json})
        assert received == ["AssetCreated"]

    def test_dispatch_item_string(self):
        """Dispatch of a raw JSON string."""
        listener = SafeguardEventListener("h", "t")
        received = []
        listener.on("Evt", lambda n, b: received.append(n))
        listener._dispatch_item(json.dumps({"Name": "Evt", "Data": ""}))
        assert received == ["Evt"]

    def test_on_signalr_event_list(self):
        """_on_signalr_event handles lists (signalrcore default)."""
        listener = SafeguardEventListener("h", "t")
        received = []
        listener.on("Evt", lambda n, b: received.append(n))
        listener._on_signalr_event([{"Name": "Evt", "Data": "x"}, {"Name": "Evt", "Data": "y"}])
        assert len(received) == 2


# ---------------------------------------------------------------------------
# PersistentSafeguardEventListener (construction, no signalr)
# ---------------------------------------------------------------------------


class TestPersistentSafeguardEventListener:
    def test_construction_with_callable(self):
        listener = PersistentSafeguardEventListener("host", lambda: "token")
        assert listener.is_started is False
        assert listener._retry_seconds == 5.0

    def test_custom_retry_seconds(self):
        listener = PersistentSafeguardEventListener("host", lambda: "token", retry_seconds=10.0)
        assert listener._retry_seconds == 10.0

    def test_fluent_on_registration(self):
        listener = PersistentSafeguardEventListener("h", lambda: "t")
        result = listener.on("Evt", lambda n, b: None)
        assert result is listener

    def test_fluent_on_state_change(self):
        listener = PersistentSafeguardEventListener("h", lambda: "t")
        result = listener.on_state_change(lambda s: None)
        assert result is listener

    def test_context_manager(self):
        listener = PersistentSafeguardEventListener("h", lambda: "t")
        with listener:
            pass
        assert not listener.is_started

    def test_stop_when_not_started_is_noop(self):
        listener = PersistentSafeguardEventListener("h", lambda: "t")
        listener.stop()
        assert not listener.is_started


# ---------------------------------------------------------------------------
# Connection.get_event_listener / get_persistent_event_listener
# ---------------------------------------------------------------------------


class TestConnectionEventListenerFactory:
    def test_get_event_listener_without_token_raises(self):
        from pysafeguard.connection import Connection

        conn = Connection("host")
        with pytest.raises(SafeguardException, match="no user token"):
            conn.get_event_listener()

    def test_get_event_listener_with_token(self):
        from pysafeguard.connection import Connection

        conn = Connection("host")
        conn.UserToken = "fake-token"
        listener = conn.get_event_listener()
        assert isinstance(listener, SafeguardEventListener)
        assert listener._access_token == "fake-token"
        assert listener._host == "host"

    def test_get_persistent_without_credentials_raises(self):
        from pysafeguard.connection import Connection

        conn = Connection("host")
        with pytest.raises(SafeguardException, match="No stored credentials"):
            conn.get_persistent_event_listener()


# ---------------------------------------------------------------------------
# Deprecated PySafeguardConnection methods
# ---------------------------------------------------------------------------


class TestDeprecatedSignalR:
    def test_register_signalr_username_emits_deprecation(self):
        from pysafeguard import PySafeguardConnection

        conn = PySafeguardConnection("host")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            try:
                PySafeguardConnection.register_signalr_username(conn, lambda r: None, "user", "pass")
            except Exception:
                pass  # Connection will fail, we only care about the warning
            deprecation_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecation_warnings) >= 1
            assert "deprecated" in str(deprecation_warnings[0].message).lower()

    def test_register_signalr_certificate_emits_deprecation(self):
        from pysafeguard import PySafeguardConnection

        conn = PySafeguardConnection("host")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            try:
                PySafeguardConnection.register_signalr_certificate(conn, lambda r: None, "cert", "key")
            except Exception:
                pass
            deprecation_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecation_warnings) >= 1
            assert "deprecated" in str(deprecation_warnings[0].message).lower()
