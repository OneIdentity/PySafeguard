"""Unit tests for error classes — WebRequestError and AsyncWebRequestError.

Mock response shapes match real Safeguard appliance responses.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

from pysafeguard.connection import WebRequestError


class TestWebRequestError:
    def _make_response(
        self,
        status_code: int = 400,
        reason: str = "Bad Request",
        method: str = "POST",
        url: str = "https://192.168.117.15/RSTS/oauth2/token",
        text: str = '{"error":"invalid_request","error_description":"Access denied.","success":false}',
    ):
        """Build a mock matching a real requests.Response from Safeguard."""
        resp = MagicMock()
        resp.status_code = status_code
        resp.reason = reason
        resp.url = url
        resp.text = text
        resp.request = SimpleNamespace(method=method)
        return resp

    def test_message_format(self):
        resp = self._make_response()
        err = WebRequestError(resp)
        assert "400 Bad Request" in err.message
        assert "POST" in err.message
        assert "RSTS/oauth2/token" in err.message
        assert "invalid_request" in err.message

    def test_message_format_login_response_error(self):
        """Match real Token/LoginResponse 400 error body."""
        resp = self._make_response(
            status_code=400,
            reason="Bad Request",
            method="POST",
            url="https://192.168.117.15/service/core/v4/Token/LoginResponse",
            text='{"Code":60519,"Message":"Invalid STS access_token."}',
        )
        err = WebRequestError(resp)
        assert "400 Bad Request" in err.message
        assert "60519" in err.message

    def test_req_attribute(self):
        resp = self._make_response()
        err = WebRequestError(resp)
        assert err.req is resp

    def test_str(self):
        resp = self._make_response(status_code=500, reason="Internal Server Error", text="internal server error")
        err = WebRequestError(resp)
        assert "500" in str(err)

    def test_inherits_exception(self):
        resp = self._make_response()
        err = WebRequestError(resp)
        assert isinstance(err, Exception)


class TestAsyncWebRequestError:
    def _make_response(
        self,
        status: int = 400,
        reason: str = "Bad Request",
        method: str = "POST",
        url: str = "https://192.168.117.15/RSTS/oauth2/token",
    ):
        """Build a mock matching a real aiohttp.ClientResponse from Safeguard."""
        resp = MagicMock()
        resp.status = status
        resp.reason = reason
        resp.method = method
        resp.url = url
        return resp

    def test_message_format(self):
        from pysafeguard.async_connection import AsyncWebRequestError

        resp = self._make_response()
        err = AsyncWebRequestError(resp)
        assert "400 Bad Request" in err.message
        assert "POST" in err.message
        assert "RSTS/oauth2/token" in err.message

    def test_req_attribute(self):
        from pysafeguard.async_connection import AsyncWebRequestError

        resp = self._make_response()
        err = AsyncWebRequestError(resp)
        assert err.req is resp

    def test_inherits_exception(self):
        from pysafeguard.async_connection import AsyncWebRequestError

        resp = self._make_response()
        err = AsyncWebRequestError(resp)
        assert isinstance(err, Exception)
