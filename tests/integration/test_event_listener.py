"""Integration tests for the event listener system against a live Safeguard appliance.

These tests verify that:
- An event listener can connect to the SignalR hub
- SafeguardClient.get_event_listener() produces a working listener
- PersistentSafeguardEventListener can authenticate and connect
- State callbacks fire correctly during lifecycle
- **Events are actually received** when appliance changes occur

Requires SPP_HOST, SPP_USERNAME, SPP_PASSWORD environment variables.
"""

import threading
import time
import uuid

import pytest

from pysafeguard import (
    EventListenerState,
    PasswordAuth,
    PersistentSafeguardEventListener,
    SafeguardClient,
    SafeguardEventListener,
    Service,
)

pytestmark = pytest.mark.integration


class TestEventListenerIntegration:
    """Test SafeguardEventListener against a live appliance."""

    def test_connect_and_disconnect(self, sync_connection):
        """Listener can connect to the SignalR hub and disconnect cleanly."""
        listener = sync_connection.get_event_listener()
        try:
            listener.start()
            assert listener.is_started
        finally:
            listener.stop()
        assert not listener.is_started

    def test_state_callback_fires(self, sync_connection):
        """State callbacks fire during start/stop lifecycle."""
        states = []
        listener = sync_connection.get_event_listener()
        listener.on_state_change(lambda s: states.append(s))

        try:
            listener.start()
            assert EventListenerState.STARTING in states
            assert EventListenerState.CONNECTED in states
        finally:
            listener.stop()

        assert EventListenerState.STOPPED in states

    def test_context_manager_cleanup(self, sync_connection):
        """Context manager stops the listener on exit."""
        listener = sync_connection.get_event_listener()
        with listener:
            listener.start()
            assert listener.is_started
        assert not listener.is_started

    def test_handler_registration_before_start(self, sync_connection):
        """Handlers can be registered before starting the listener."""
        received = []
        listener = sync_connection.get_event_listener()
        listener.on("AssetCreated", lambda n, b: received.append(n))

        with listener:
            listener.start()
            assert listener.is_started
            # We don't expect to actually receive events in this test,
            # but the listener should be connected and ready.
            time.sleep(1)

    def test_double_start_is_noop(self, sync_connection):
        """Calling start() twice does not raise or create duplicate connections."""
        listener = sync_connection.get_event_listener()
        with listener:
            listener.start()
            listener.start()  # should not raise
            assert listener.is_started

    def test_double_stop_is_noop(self, sync_connection):
        """Calling stop() twice does not raise."""
        listener = sync_connection.get_event_listener()
        listener.start()
        listener.stop()
        listener.stop()  # should not raise


class TestPersistentEventListenerIntegration:
    """Test PersistentSafeguardEventListener against a live appliance."""

    def test_from_password_connect(self, spp_host, spp_username, spp_password, spp_verify):
        """Persistent listener can authenticate and connect via password."""
        states = []
        listener = PersistentSafeguardEventListener.from_password(spp_host, spp_username, spp_password, verify=spp_verify)
        listener.on_state_change(lambda s: states.append(s))

        try:
            listener.start()
            assert listener.is_started
            # Give SignalR time to fully connect
            time.sleep(2)
            assert EventListenerState.CONNECTED in states
        finally:
            listener.stop()

        assert EventListenerState.STOPPED in states

    def test_context_manager(self, spp_host, spp_username, spp_password, spp_verify):
        """Persistent listener works as a context manager."""
        with PersistentSafeguardEventListener.from_password(spp_host, spp_username, spp_password, verify=spp_verify) as listener:
            listener.start()
            time.sleep(1)
            assert listener.is_started
        assert not listener.is_started

    def test_stop_prevents_reconnect(self, spp_host, spp_username, spp_password, spp_verify):
        """After stop(), the persistent listener does not attempt reconnection."""
        states = []
        listener = PersistentSafeguardEventListener.from_password(spp_host, spp_username, spp_password, verify=spp_verify)
        listener.on_state_change(lambda s: states.append(s))

        listener.start()
        time.sleep(1)
        listener.stop()
        time.sleep(2)

        # No RECONNECTING state after intentional stop
        states_after_stop = states[states.index(EventListenerState.STOPPED) :] if EventListenerState.STOPPED in states else []
        assert EventListenerState.RECONNECTING not in states_after_stop


class TestConnectionGetEventListener:
    """Test the SafeguardClient factory methods for event listeners."""

    def test_get_event_listener(self, sync_connection):
        """SafeguardClient.get_event_listener() returns a working listener."""
        listener = sync_connection.get_event_listener()
        assert isinstance(listener, SafeguardEventListener)

        with listener:
            listener.start()
            assert listener.is_started

    def test_get_persistent_event_listener(self, sync_connection):
        """SafeguardClient.get_persistent_event_listener() returns a working persistent listener."""
        listener = sync_connection.get_persistent_event_listener()
        assert isinstance(listener, PersistentSafeguardEventListener)

        with listener:
            listener.start()
            time.sleep(1)
            assert listener.is_started


# ===========================================================================
# Event reception — verify events are actually delivered
# ===========================================================================


class TestEventReception:
    """Test that events are actually received when appliance changes occur."""

    def test_receive_user_created_event(self, spp_host, spp_username, spp_password, spp_verify):
        """Create a user and verify the UserCreated event is received."""
        client = SafeguardClient(spp_host, auth=PasswordAuth("local", spp_username, spp_password), verify=spp_verify)
        client.login()

        received = []
        event = threading.Event()
        listener = client.get_event_listener()
        listener.on("UserCreated", lambda name, body: (received.append((name, body)), event.set()))

        try:
            listener.start()
            time.sleep(2)  # wait for SignalR connection

            name = f"PySg_EvtRx_{uuid.uuid4().hex[:6]}"
            r = client.post(Service.CORE, "Users", json={"Name": name, "PrimaryAuthenticationProvider": {"Id": -1}})
            assert r.status_code == 201
            user_id = r.json()["Id"]

            assert event.wait(timeout=10), "Timed out waiting for UserCreated event"
            assert len(received) >= 1
            assert received[0][0] == "UserCreated"
            assert name in received[0][1]

            # Cleanup
            client.delete(Service.CORE, f"Users/{user_id}")
        finally:
            listener.stop()

    def test_receive_multiple_events(self, spp_host, spp_username, spp_password, spp_verify):
        """Create and delete a user — receive both UserCreated and UserDeleted."""
        client = SafeguardClient(spp_host, auth=PasswordAuth("local", spp_username, spp_password), verify=spp_verify)
        client.login()

        event_names: list[str] = []
        all_received = threading.Event()
        listener = client.get_event_listener()

        def handler(name, body):
            event_names.append(name)
            if len(event_names) >= 2:
                all_received.set()

        listener.on("UserCreated", handler)
        listener.on("UserDeleted", handler)

        try:
            listener.start()
            time.sleep(2)

            name = f"PySg_EvtMulti_{uuid.uuid4().hex[:6]}"
            r = client.post(Service.CORE, "Users", json={"Name": name, "PrimaryAuthenticationProvider": {"Id": -1}})
            assert r.status_code == 201
            user_id = r.json()["Id"]

            time.sleep(2)
            client.delete(Service.CORE, f"Users/{user_id}")

            assert all_received.wait(timeout=10), f"Only received {event_names}, expected 2+ events"
            assert "UserCreated" in event_names
            assert "UserDeleted" in event_names
        finally:
            listener.stop()

    def test_persistent_listener_receives_events(self, spp_host, spp_username, spp_password, spp_verify):
        """PersistentSafeguardEventListener also receives events."""
        client = SafeguardClient(spp_host, auth=PasswordAuth("local", spp_username, spp_password), verify=spp_verify)
        client.login()

        received = []
        event = threading.Event()
        listener = PersistentSafeguardEventListener.from_password(spp_host, spp_username, spp_password, verify=spp_verify)
        listener.on("UserCreated", lambda name, body: (received.append(name), event.set()))

        try:
            listener.start()
            time.sleep(2)

            name = f"PySg_PersEvt_{uuid.uuid4().hex[:6]}"
            r = client.post(Service.CORE, "Users", json={"Name": name, "PrimaryAuthenticationProvider": {"Id": -1}})
            assert r.status_code == 201
            user_id = r.json()["Id"]

            assert event.wait(timeout=10), "PersistentListener did not receive UserCreated"
            assert "UserCreated" in received

            client.delete(Service.CORE, f"Users/{user_id}")
        finally:
            listener.stop()

    def test_listener_stays_connected(self, sync_connection):
        """Listener remains connected and is_started=True for an extended period."""
        listener = sync_connection.get_event_listener()
        try:
            listener.start()
            assert listener.is_started
            time.sleep(5)
            assert listener.is_started, "Listener disconnected unexpectedly"
        finally:
            listener.stop()
