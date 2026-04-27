"""Unit tests for Connection and AsyncConnection __init__ defaults."""

from pysafeguard.connection import Connection


class TestConnectionInit:
    def test_default_attributes(self):
        conn = Connection("myhost")
        assert conn.host == "myhost"
        assert conn.UserToken is None
        assert conn.apiVersion == "v4"
        assert conn.verify is True
        assert "accept" in conn.headers
        assert conn.headers["accept"] == "application/json"

    def test_custom_verify_path(self):
        conn = Connection("host", verify="/path/to/ca.pem")
        assert conn.verify == "/path/to/ca.pem"

    def test_verify_false(self):
        conn = Connection("host", verify=False)
        assert conn.verify is False

    def test_custom_api_version(self):
        conn = Connection("host", apiVersion="v3")
        assert conn.apiVersion == "v3"

    def test_none_host(self):
        conn = Connection(None)
        assert conn.host is None

    def test_connect_token_sets_header(self):
        conn = Connection("host")
        conn.connect_token("my-token-value")
        assert conn.UserToken == "my-token-value"
        assert conn.headers["authorization"] == "Bearer my-token-value"

    def test_connect_token_none(self):
        conn = Connection("host")
        conn.connect_token(None)
        assert conn.UserToken is None


class TestAsyncConnectionInit:
    def test_default_attributes(self):
        from pysafeguard.async_connection import AsyncConnection

        conn = AsyncConnection("myhost")
        assert conn.host == "myhost"
        assert conn.UserToken is None
        assert conn.apiVersion == "v4"
        assert conn.verify is True
        assert conn.headers["accept"] == "application/json"

    def test_custom_verify_false(self):
        from pysafeguard.async_connection import AsyncConnection

        conn = AsyncConnection("host", verify=False)
        assert conn.verify is False

    def test_connect_token(self):
        from pysafeguard.async_connection import AsyncConnection

        conn = AsyncConnection("host")
        conn.connect_token("async-token")
        assert conn.UserToken == "async-token"
        assert conn.headers["authorization"] == "Bearer async-token"
