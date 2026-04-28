"""Integration tests for the event listener system against a live Safeguard appliance.

These tests verify that:
- An event listener can connect to the SignalR hub
- SafeguardClient.get_event_listener() produces a working listener
- PersistentSafeguardEventListener can authenticate and connect
- State callbacks fire correctly during lifecycle

Requires SPP_HOST, SPP_USERNAME, SPP_PASSWORD environment variables.
"""

import time

import pytest

from pysafeguard import (
    EventListenerState,
    PersistentSafeguardEventListener,
    SafeguardEventListener,
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
