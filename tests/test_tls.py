# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Tests for TLS 1.3 support: async post-handshake auth and TLS version pinning.

Covers the fix from issues #41/#43 (async cert auth on TLS 1.3) and the
opt-in ``min_tls_version`` / ``max_tls_version`` controls on both clients
and the A2A contexts.
"""

from __future__ import annotations

import ssl

from requests.adapters import HTTPAdapter

from pysafeguard.a2a import A2AContext
from pysafeguard.async_client import AsyncSafeguardClient
from pysafeguard.client import SafeguardClient, _TlsVersionAdapter


class TestAsyncSslContext:
    def test_post_handshake_auth_enabled(self):
        """The async cert-auth context must answer TLS 1.3 post-handshake auth."""
        client = AsyncSafeguardClient("host", verify=False)
        ctx = client._create_ssl_context(cert=None)
        # verify=False with no cert and no pins still returns False (no context).
        assert ctx is False

        secure = AsyncSafeguardClient("host")
        ctx = secure._create_ssl_context(cert=None)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.post_handshake_auth is True

    def test_default_no_version_pin(self):
        client = AsyncSafeguardClient("host")
        ctx = client._create_ssl_context(cert=None)
        assert isinstance(ctx, ssl.SSLContext)
        # No explicit pin: minimum stays at the library default (TLS 1.2).
        assert ctx.maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED

    def test_min_tls_version_applied(self):
        client = AsyncSafeguardClient("host", min_tls_version=ssl.TLSVersion.TLSv1_3)
        ctx = client._create_ssl_context(cert=None)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
        assert ctx.post_handshake_auth is True

    def test_max_tls_version_applied(self):
        client = AsyncSafeguardClient("host", max_tls_version=ssl.TLSVersion.TLSv1_2)
        ctx = client._create_ssl_context(cert=None)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.maximum_version == ssl.TLSVersion.TLSv1_2

    def test_version_pin_forces_context_even_without_verify(self):
        """A pin must build a real context even when verify=False and no cert."""
        client = AsyncSafeguardClient("host", verify=False, min_tls_version=ssl.TLSVersion.TLSv1_3)
        ctx = client._create_ssl_context(cert=None)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
        assert ctx.verify_mode == ssl.CERT_NONE


class TestSyncTlsAdapter:
    def test_default_uses_stock_adapter(self):
        client = SafeguardClient("host")
        adapter = client._session.get_adapter("https://host")
        assert type(adapter) is HTTPAdapter
        client.close()

    def test_min_pin_mounts_version_adapter(self):
        client = SafeguardClient("host", min_tls_version=ssl.TLSVersion.TLSv1_3)
        adapter = client._session.get_adapter("https://host")
        assert isinstance(adapter, _TlsVersionAdapter)
        assert adapter.poolmanager.connection_pool_kw["ssl_minimum_version"] == ssl.TLSVersion.TLSv1_3
        client.close()

    def test_max_pin_mounts_version_adapter(self):
        client = SafeguardClient("host", max_tls_version=ssl.TLSVersion.TLSv1_2)
        adapter = client._session.get_adapter("https://host")
        assert isinstance(adapter, _TlsVersionAdapter)
        assert adapter.poolmanager.connection_pool_kw["ssl_maximum_version"] == ssl.TLSVersion.TLSv1_2
        client.close()

    def test_both_pins_mounted(self):
        client = SafeguardClient(
            "host",
            min_tls_version=ssl.TLSVersion.TLSv1_2,
            max_tls_version=ssl.TLSVersion.TLSv1_3,
        )
        adapter = client._session.get_adapter("https://host")
        assert isinstance(adapter, _TlsVersionAdapter)
        kw = adapter.poolmanager.connection_pool_kw
        assert kw["ssl_minimum_version"] == ssl.TLSVersion.TLSv1_2
        assert kw["ssl_maximum_version"] == ssl.TLSVersion.TLSv1_3
        client.close()


class TestA2ATlsForwarding:
    def test_sync_a2a_forwards_pins(self):
        ctx = A2AContext(
            "host",
            "cert.pem",
            "key.pem",
            verify=False,
            min_tls_version=ssl.TLSVersion.TLSv1_3,
        )
        assert ctx._conn._min_tls_version == ssl.TLSVersion.TLSv1_3
        adapter = ctx._conn._session.get_adapter("https://host")
        assert isinstance(adapter, _TlsVersionAdapter)
        ctx.close()

    def test_async_a2a_forwards_pins(self):
        from pysafeguard.async_a2a import AsyncA2AContext

        ctx = AsyncA2AContext(
            "host",
            "cert.pem",
            "key.pem",
            verify=False,
            max_tls_version=ssl.TLSVersion.TLSv1_2,
        )
        assert ctx._conn._max_tls_version == ssl.TLSVersion.TLSv1_2
