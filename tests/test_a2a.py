"""Tests for A2AContext and AsyncA2AContext construction and validation logic.

These are pure-logic tests that do not require a live appliance or A2A
registrations.  Integration tests for actual credential retrieval would
require an A2A-configured appliance with cert auth.
"""

from __future__ import annotations

import pytest

from pysafeguard.a2a import A2AContext
from pysafeguard.async_a2a import AsyncA2AContext
from pysafeguard.event import PersistentSafeguardEventListener, SafeguardEventListener


# ---------------------------------------------------------------------------
# A2AContext construction
# ---------------------------------------------------------------------------


class TestA2AContextConstruction:
    def test_basic_construction(self):
        ctx = A2AContext("host", "cert.pem", "key.pem")
        assert ctx._host == "host"
        assert ctx._cert == ("cert.pem", "key.pem")
        assert ctx._verify is True
        assert ctx._user_authenticated is False
        ctx.close()

    def test_custom_verify_and_version(self):
        ctx = A2AContext("host", "c.pem", "k.pem", verify=False, api_version="v3")
        assert ctx._verify is False
        assert ctx._api_version == "v3"
        ctx.close()

    def test_empty_cert_raises(self):
        with pytest.raises(ValueError, match="cert_file and key_file"):
            A2AContext("host", "", "key.pem")

    def test_empty_key_raises(self):
        with pytest.raises(ValueError, match="cert_file and key_file"):
            A2AContext("host", "cert.pem", "")

    def test_context_manager(self):
        with A2AContext("host", "c.pem", "k.pem") as ctx:
            assert ctx._host == "host"
        # close() was called (no error means it worked)


class TestA2AContextValidation:
    def test_empty_api_key_raises_on_retrieve(self):
        with A2AContext("host", "c.pem", "k.pem") as ctx:
            with pytest.raises(ValueError, match="api_key"):
                ctx.retrieve_password("")

    def test_empty_api_key_raises_on_set(self):
        with A2AContext("host", "c.pem", "k.pem") as ctx:
            with pytest.raises(ValueError, match="api_key"):
                ctx.set_password("", "newpass")


class TestA2AContextEventListeners:
    def test_get_event_listener_returns_listener(self):
        with A2AContext("host", "c.pem", "k.pem") as ctx:
            listener = ctx.get_event_listener("my-api-key")
            assert isinstance(listener, SafeguardEventListener)
            assert listener._api_key == "my-api-key"

    def test_get_persistent_event_listener_returns_persistent(self):
        with A2AContext("host", "c.pem", "k.pem") as ctx:
            listener = ctx.get_persistent_event_listener("my-api-key")
            assert isinstance(listener, PersistentSafeguardEventListener)

    def test_event_listener_host_matches(self):
        with A2AContext("myhost", "c.pem", "k.pem") as ctx:
            listener = ctx.get_event_listener("key")
            assert listener._host == "myhost"


class TestA2AContextLazyAuth:
    def test_not_authenticated_on_construction(self):
        with A2AContext("host", "c.pem", "k.pem") as ctx:
            assert ctx._user_authenticated is False


# ---------------------------------------------------------------------------
# AsyncA2AContext construction
# ---------------------------------------------------------------------------


class TestAsyncA2AContextConstruction:
    def test_basic_construction(self):
        ctx = AsyncA2AContext("host", "cert.pem", "key.pem")
        assert ctx._host == "host"
        assert ctx._cert == ("cert.pem", "key.pem")
        assert ctx._user_authenticated is False

    def test_empty_cert_raises(self):
        with pytest.raises(ValueError, match="cert_file and key_file"):
            AsyncA2AContext("host", "", "key.pem")

    def test_empty_key_raises(self):
        with pytest.raises(ValueError, match="cert_file and key_file"):
            AsyncA2AContext("host", "cert.pem", "")

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        async with AsyncA2AContext("host", "c.pem", "k.pem") as ctx:
            assert ctx._host == "host"

    @pytest.mark.asyncio
    async def test_empty_api_key_raises_on_retrieve(self):
        async with AsyncA2AContext("host", "c.pem", "k.pem") as ctx:
            with pytest.raises(ValueError, match="api_key"):
                await ctx.retrieve_password("")

    def test_get_event_listener(self):
        ctx = AsyncA2AContext("host", "c.pem", "k.pem")
        listener = ctx.get_event_listener("my-key")
        assert isinstance(listener, SafeguardEventListener)
        assert listener._api_key == "my-key"

    def test_get_persistent_event_listener(self):
        ctx = AsyncA2AContext("host", "c.pem", "k.pem")
        listener = ctx.get_persistent_event_listener("my-key")
        assert isinstance(listener, PersistentSafeguardEventListener)
