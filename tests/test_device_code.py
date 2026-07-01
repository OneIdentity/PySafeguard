# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Tests for the Device Authorization Grant (RFC 8628) login flow.

Covers the sync (:mod:`pysafeguard.device_code`) and async
(:mod:`pysafeguard.async_device_code`) implementations plus the
:class:`pysafeguard.auth.DeviceCodeAuth` strategy. No live appliance is
required — all rSTS HTTP transport is mocked.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pysafeguard import DeviceCodeAuth, DeviceCodeInfo
from pysafeguard.auth import Auth, TokenAuth
from pysafeguard.errors import SafeguardError
from pysafeguard.hidden_string import HiddenString

# ---------------------------------------------------------------------------
# Canonical rSTS payloads
# ---------------------------------------------------------------------------

_DEVICE_LOGIN_JSON: dict[str, Any] = {
    "device_code": "secret-device-code",
    "user_code": "WDJB-MJHT",
    "verification_uri": "https://appliance/RSTS/DeviceLogin",
    "verification_uri_complete": "https://appliance/RSTS/DeviceLogin?code=WDJB-MJHT",
    "expires_in": 300,
}

_DISABLED_HTML = (
    "<html><head><title>Error</title></head><body>"
    "OAuth2 device code grant type is not allowed."
    "</body></html>"
)

_LOGIN_RESPONSE_JSON: dict[str, Any] = {"Status": "Success", "UserToken": "the-user-token"}


# ---------------------------------------------------------------------------
# Sync fakes
# ---------------------------------------------------------------------------


class FakeResponse:
    """Minimal stand-in for ``requests.Response``."""

    def __init__(self, status_code: int, *, json_data: Any = None, text: str | None = None, json_raises: bool = False) -> None:
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self._json_data = json_data
        self._json_raises = json_raises
        if text is not None:
            self.text = text
        elif json_data is not None:
            self.text = json.dumps(json_data)
        else:
            self.text = ""

    def json(self) -> Any:
        if self._json_raises:
            raise AssertionError("json() must not be called on this response")
        if self._json_data is None:
            raise ValueError("no json body")
        return self._json_data


def _ok_login() -> FakeResponse:
    return FakeResponse(200, json_data=_LOGIN_RESPONSE_JSON)


def _make_sync_session(*, device_login: FakeResponse, poll_responses: list[FakeResponse], login_response: FakeResponse | None = None) -> MagicMock:
    """Build a fake ``requests.Session`` dispatching by URL."""
    poll_iter = iter(poll_responses)
    login = login_response if login_response is not None else _ok_login()

    def post(url: str, **kwargs: Any) -> FakeResponse:
        if "DeviceLogin" in url:
            return device_login
        if "Token/LoginResponse" in url:
            return login
        if "oauth2/token" in url:
            return next(poll_iter)
        raise AssertionError(f"unexpected url {url}")

    session = MagicMock()
    session.post.side_effect = post
    session.__enter__.return_value = session
    session.__exit__.return_value = False
    return session


# ---------------------------------------------------------------------------
# Async fakes
# ---------------------------------------------------------------------------


class FakeAsyncResponse:
    """Async context-manager stand-in for ``aiohttp.ClientResponse``."""

    def __init__(self, status: int, *, json_data: Any = None, text: str | None = None) -> None:
        self.status = status
        self._json_data = json_data
        if text is not None:
            self._text = text
        elif json_data is not None:
            self._text = json.dumps(json_data)
        else:
            self._text = ""

    async def text(self) -> str:
        return self._text

    async def json(self, content_type: Any = None) -> Any:
        if self._json_data is None:
            raise ValueError("no json body")
        return self._json_data

    async def __aenter__(self) -> FakeAsyncResponse:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False


class FakeAsyncSession:
    """Async context-manager stand-in for ``aiohttp.ClientSession``."""

    def __init__(self, *, device_login: FakeAsyncResponse, poll_responses: list[FakeAsyncResponse], login_response: FakeAsyncResponse) -> None:
        self._device_login = device_login
        self._poll = iter(poll_responses)
        self._login = login_response

    def post(self, url: str, **kwargs: Any) -> FakeAsyncResponse:
        if "DeviceLogin" in url:
            return self._device_login
        if "Token/LoginResponse" in url:
            return self._login
        if "oauth2/token" in url:
            return next(self._poll)
        raise AssertionError(f"unexpected url {url}")

    async def __aenter__(self) -> FakeAsyncSession:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False


def _async_device_login(**overrides: Any) -> FakeAsyncResponse:
    data = {**_DEVICE_LOGIN_JSON, **overrides}
    return FakeAsyncResponse(200, json_data=data)


def _async_ok_login() -> FakeAsyncResponse:
    return FakeAsyncResponse(200, json_data=_LOGIN_RESPONSE_JSON)


# ===========================================================================
# DeviceCodeInfo
# ===========================================================================


class TestDeviceCodeInfo:
    def test_from_device_login_defaults_interval(self) -> None:
        info = DeviceCodeInfo.from_device_login(dict(_DEVICE_LOGIN_JSON), default_interval=7)
        assert info.user_code == "WDJB-MJHT"
        assert info.verification_uri == _DEVICE_LOGIN_JSON["verification_uri"]
        assert info.verification_uri_complete == _DEVICE_LOGIN_JSON["verification_uri_complete"]
        assert info.expires_in == 300
        # interval absent in payload -> falls back to default
        assert info.interval == 7

    def test_from_device_login_uses_response_interval(self) -> None:
        info = DeviceCodeInfo.from_device_login({**_DEVICE_LOGIN_JSON, "interval": 10}, default_interval=5)
        assert info.interval == 10

    def test_from_device_login_does_not_expose_device_code(self) -> None:
        info = DeviceCodeInfo.from_device_login(dict(_DEVICE_LOGIN_JSON), default_interval=5)
        assert not hasattr(info, "device_code")

    @pytest.mark.parametrize("missing", ["user_code", "verification_uri", "verification_uri_complete"])
    def test_from_device_login_missing_display_field(self, missing: str) -> None:
        payload = dict(_DEVICE_LOGIN_JSON)
        del payload[missing]
        with pytest.raises(SafeguardError, match=missing):
            DeviceCodeInfo.from_device_login(payload, default_interval=5)

    def test_from_device_login_non_integer_expires_in(self) -> None:
        with pytest.raises(SafeguardError, match="expires_in"):
            DeviceCodeInfo.from_device_login({**_DEVICE_LOGIN_JSON, "expires_in": "soon"}, default_interval=5)

    def test_from_device_login_non_integer_interval(self) -> None:
        with pytest.raises(SafeguardError, match="interval"):
            DeviceCodeInfo.from_device_login({**_DEVICE_LOGIN_JSON, "interval": "fast"}, default_interval=5)

    def test_from_device_login_non_dict(self) -> None:
        with pytest.raises(SafeguardError):
            DeviceCodeInfo.from_device_login(["not", "a", "dict"], default_interval=5)

    def test_is_frozen(self) -> None:
        info = DeviceCodeInfo.from_device_login(dict(_DEVICE_LOGIN_JSON), default_interval=5)
        with pytest.raises(Exception):
            info.user_code = "changed"  # type: ignore[misc]


# ===========================================================================
# Sync flow: get_device_code_token
# ===========================================================================


class TestSyncDeviceCodeFlow:
    def test_disabled_grant_detected_without_json_parse(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Disabled grant returns HTML; detection must not call resp.json()."""
        from pysafeguard import device_code as dc

        # json_raises=True asserts the disabled path never parses JSON.
        device_login = FakeResponse(400, text=_DISABLED_HTML, json_raises=True)
        session = _make_sync_session(device_login=device_login, poll_responses=[])

        callback = MagicMock()
        with patch.object(dc, "Session", return_value=session):
            with pytest.raises(SafeguardError, match="not allowed"):
                dc.get_device_code_token("appliance", on_device_code=callback)

        callback.assert_not_called()
        # The library performs no display I/O.
        assert capsys.readouterr().out == ""

    def test_callback_invoked_once_and_no_library_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        from pysafeguard import device_code as dc

        device_login = FakeResponse(200, json_data=dict(_DEVICE_LOGIN_JSON))
        success = FakeResponse(200, json_data={"access_token": "rsts-token"})
        session = _make_sync_session(device_login=device_login, poll_responses=[success])

        received: list[DeviceCodeInfo] = []
        with patch.object(dc, "Session", return_value=session):
            with patch.object(dc.time, "sleep"):
                token = dc.get_device_code_token("appliance", on_device_code=received.append)

        assert token == "the-user-token"
        assert len(received) == 1
        assert isinstance(received[0], DeviceCodeInfo)
        assert received[0].user_code == "WDJB-MJHT"
        # The callback (test code) printed nothing, and neither did the library.
        assert capsys.readouterr().out == ""

    def test_poll_transitions_pending_slowdown_success(self) -> None:
        """authorization_pending -> slow_down (interval bump) -> success."""
        from pysafeguard import device_code as dc

        device_login = FakeResponse(200, json_data=dict(_DEVICE_LOGIN_JSON))
        poll_responses = [
            FakeResponse(400, json_data={"error": "authorization_pending"}),
            FakeResponse(400, json_data={"error": "slow_down"}),
            FakeResponse(200, json_data={"access_token": "rsts-token"}),
        ]
        session = _make_sync_session(device_login=device_login, poll_responses=poll_responses)

        sleeps: list[float] = []
        with patch.object(dc, "Session", return_value=session):
            with patch.object(dc.time, "sleep", side_effect=lambda s: sleeps.append(s)):
                token = dc.get_device_code_token("appliance", on_device_code=lambda i: None, polling_interval=5)

        assert token == "the-user-token"
        # Two sleeps before success; the second is bumped by 5 after slow_down.
        assert sleeps == [5, 10]

    def test_access_denied_raises(self) -> None:
        from pysafeguard import device_code as dc

        device_login = FakeResponse(200, json_data=dict(_DEVICE_LOGIN_JSON))
        poll_responses = [FakeResponse(400, json_data={"error": "access_denied"})]
        session = _make_sync_session(device_login=device_login, poll_responses=poll_responses)

        with patch.object(dc, "Session", return_value=session):
            with patch.object(dc.time, "sleep"):
                with pytest.raises(SafeguardError, match="denied"):
                    dc.get_device_code_token("appliance", on_device_code=lambda i: None)

    def test_expired_token_raises(self) -> None:
        from pysafeguard import device_code as dc

        device_login = FakeResponse(200, json_data=dict(_DEVICE_LOGIN_JSON))
        poll_responses = [FakeResponse(400, json_data={"error": "expired_token"})]
        session = _make_sync_session(device_login=device_login, poll_responses=poll_responses)

        with patch.object(dc, "Session", return_value=session):
            with patch.object(dc.time, "sleep"):
                with pytest.raises(SafeguardError, match="expired"):
                    dc.get_device_code_token("appliance", on_device_code=lambda i: None)

    def test_deadline_exceeded_from_expires_in(self) -> None:
        """A short expires_in deadline aborts the poll loop with a timeout error."""
        from pysafeguard import device_code as dc

        device_login = FakeResponse(200, json_data={**_DEVICE_LOGIN_JSON, "expires_in": 10})
        poll_responses = [FakeResponse(400, json_data={"error": "authorization_pending"})]
        session = _make_sync_session(device_login=device_login, poll_responses=poll_responses)

        # monotonic: deadline=10; loop check(1)<10; remaining=10-2=8; loop check(11)>=10 -> timeout
        monotonic_values = iter([0, 1, 2, 11])
        with patch.object(dc, "Session", return_value=session):
            with patch.object(dc.time, "sleep"):
                with patch.object(dc.time, "monotonic", side_effect=lambda: next(monotonic_values)):
                    with pytest.raises(SafeguardError, match="timed out"):
                        dc.get_device_code_token("appliance", on_device_code=lambda i: None)

    def test_is_cancelled_aborts_before_polling(self) -> None:
        from pysafeguard import device_code as dc

        device_login = FakeResponse(200, json_data=dict(_DEVICE_LOGIN_JSON))
        # No poll responses: cancellation must abort before any token POST.
        session = _make_sync_session(device_login=device_login, poll_responses=[])

        with patch.object(dc, "Session", return_value=session):
            with patch.object(dc.time, "sleep"):
                with pytest.raises(SafeguardError, match="cancelled"):
                    dc.get_device_code_token("appliance", on_device_code=lambda i: None, is_cancelled=lambda: True)

    def test_rsts_token_exchanged_for_user_token(self) -> None:
        """The rSTS access token is exchanged through Token/LoginResponse."""
        from pysafeguard import device_code as dc

        device_login = FakeResponse(200, json_data=dict(_DEVICE_LOGIN_JSON))
        success = FakeResponse(200, json_data={"access_token": "rsts-token"})
        login_response = FakeResponse(200, json_data={"Status": "Success", "UserToken": "exchanged-user-token"})
        session = _make_sync_session(device_login=device_login, poll_responses=[success], login_response=login_response)

        with patch.object(dc, "Session", return_value=session):
            with patch.object(dc.time, "sleep"):
                token = dc.get_device_code_token("appliance", on_device_code=lambda i: None)

        assert token == "exchanged-user-token"
        # Verify the device-code grant body was posted to the token endpoint.
        token_calls = [c for c in session.post.call_args_list if "oauth2/token" in c.args[0]]
        assert token_calls
        body = token_calls[0].kwargs["json"]
        assert body["grant_type"] == dc.DEVICE_CODE_GRANT_TYPE
        assert body["device_code"] == "secret-device-code"

    def test_non_positive_polling_interval_rejected(self) -> None:
        from pysafeguard import device_code as dc

        with pytest.raises(SafeguardError, match="polling_interval"):
            dc.get_device_code_token("appliance", on_device_code=lambda i: None, polling_interval=0)


# ===========================================================================
# Async flow: async_get_device_code_token
# ===========================================================================


class TestAsyncDeviceCodeFlow:
    async def test_success_with_sync_callback(self) -> None:
        from pysafeguard import async_device_code as adc

        session = FakeAsyncSession(
            device_login=_async_device_login(),
            poll_responses=[FakeAsyncResponse(200, json_data={"access_token": "rsts-token"})],
            login_response=_async_ok_login(),
        )
        received: list[DeviceCodeInfo] = []
        with patch.object(adc, "ClientSession", return_value=session):
            with patch.object(adc.asyncio, "sleep", new=AsyncMock()):
                token = await adc.async_get_device_code_token("appliance", on_device_code=received.append, verify=False)

        assert token == "the-user-token"
        assert len(received) == 1
        assert isinstance(received[0], DeviceCodeInfo)

    async def test_awaitable_callback_is_awaited(self) -> None:
        from pysafeguard import async_device_code as adc

        session = FakeAsyncSession(
            device_login=_async_device_login(),
            poll_responses=[FakeAsyncResponse(200, json_data={"access_token": "rsts-token"})],
            login_response=_async_ok_login(),
        )

        awaited: list[DeviceCodeInfo] = []

        async def async_callback(info: DeviceCodeInfo) -> None:
            awaited.append(info)

        with patch.object(adc, "ClientSession", return_value=session):
            with patch.object(adc.asyncio, "sleep", new=AsyncMock()):
                token = await adc.async_get_device_code_token("appliance", on_device_code=async_callback, verify=False)

        assert token == "the-user-token"
        assert len(awaited) == 1
        assert isinstance(awaited[0], DeviceCodeInfo)

    async def test_poll_transitions_pending_slowdown_success(self) -> None:
        from pysafeguard import async_device_code as adc

        session = FakeAsyncSession(
            device_login=_async_device_login(),
            poll_responses=[
                FakeAsyncResponse(400, json_data={"error": "authorization_pending"}),
                FakeAsyncResponse(400, json_data={"error": "slow_down"}),
                FakeAsyncResponse(200, json_data={"access_token": "rsts-token"}),
            ],
            login_response=_async_ok_login(),
        )

        sleep_mock = AsyncMock()
        with patch.object(adc, "ClientSession", return_value=session):
            with patch.object(adc.asyncio, "sleep", new=sleep_mock):
                token = await adc.async_get_device_code_token("appliance", on_device_code=lambda i: None, polling_interval=5, verify=False)

        assert token == "the-user-token"
        slept = [call.args[0] for call in sleep_mock.await_args_list]
        assert slept == [5, 10]

    async def test_disabled_grant_detected(self) -> None:
        from pysafeguard import async_device_code as adc

        session = FakeAsyncSession(
            device_login=FakeAsyncResponse(400, text=_DISABLED_HTML),
            poll_responses=[],
            login_response=_async_ok_login(),
        )
        callback = MagicMock()
        with patch.object(adc, "ClientSession", return_value=session):
            with pytest.raises(SafeguardError, match="not allowed"):
                await adc.async_get_device_code_token("appliance", on_device_code=callback, verify=False)
        callback.assert_not_called()

    async def test_access_denied_raises(self) -> None:
        from pysafeguard import async_device_code as adc

        session = FakeAsyncSession(
            device_login=_async_device_login(),
            poll_responses=[FakeAsyncResponse(400, json_data={"error": "access_denied"})],
            login_response=_async_ok_login(),
        )
        with patch.object(adc, "ClientSession", return_value=session):
            with patch.object(adc.asyncio, "sleep", new=AsyncMock()):
                with pytest.raises(SafeguardError, match="denied"):
                    await adc.async_get_device_code_token("appliance", on_device_code=lambda i: None, verify=False)

    async def test_is_cancelled_aborts(self) -> None:
        from pysafeguard import async_device_code as adc

        session = FakeAsyncSession(
            device_login=_async_device_login(),
            poll_responses=[],
            login_response=_async_ok_login(),
        )
        with patch.object(adc, "ClientSession", return_value=session):
            with patch.object(adc.asyncio, "sleep", new=AsyncMock()):
                with pytest.raises(SafeguardError, match="cancelled"):
                    await adc.async_get_device_code_token("appliance", on_device_code=lambda i: None, is_cancelled=lambda: True, verify=False)


# ===========================================================================
# DeviceCodeAuth strategy
# ===========================================================================


class TestDeviceCodeAuth:
    def test_is_auth_protocol(self) -> None:
        assert isinstance(DeviceCodeAuth(lambda i: None), Auth)

    def test_frozen(self) -> None:
        auth = DeviceCodeAuth(lambda i: None)
        with pytest.raises(Exception):
            auth.scope = "x"  # type: ignore[misc]

    def test_callback_is_required(self) -> None:
        with pytest.raises(TypeError):
            DeviceCodeAuth()  # type: ignore[call-arg]

    def test_keyword_only_options(self) -> None:
        with pytest.raises(TypeError):
            DeviceCodeAuth(lambda i: None, "local")  # type: ignore[misc]

    def test_can_refresh_is_false(self) -> None:
        assert DeviceCodeAuth(lambda i: None).can_refresh is False

    def test_no_hidden_string_fields(self) -> None:
        import dataclasses

        auth = DeviceCodeAuth(lambda i: None, scope="s", client_id="c", polling_interval=9)
        for f in dataclasses.fields(auth):
            assert not isinstance(getattr(auth, f.name), HiddenString)

    def test_no_dispose_method(self) -> None:
        # No stored secret, so unlike the other strategies there is no dispose().
        assert not hasattr(DeviceCodeAuth(lambda i: None), "dispose")

    def test_refresh_raises_like_token_auth(self) -> None:
        auth = DeviceCodeAuth(lambda i: None)
        client = MagicMock()
        with pytest.raises(SafeguardError):
            auth.refresh(client)
        # Same behavior as TokenAuth.
        assert TokenAuth("t").can_refresh is False

    async def test_async_refresh_raises(self) -> None:
        auth = DeviceCodeAuth(lambda i: None)
        client = MagicMock()
        with pytest.raises(SafeguardError):
            await auth.async_refresh(client)

    def test_authenticate_delegates_to_flow(self) -> None:
        from pysafeguard import device_code as dc

        callback = MagicMock()
        auth = DeviceCodeAuth(callback, scope="custom-scope", client_id="cid", polling_interval=8)
        client = MagicMock()
        client.host = "appliance.example.com"
        client.verify = False
        client.api_version = "v4"

        with patch.object(dc, "get_device_code_token", return_value="user-token") as mock_flow:
            result = auth.authenticate(client)

        assert result == "user-token"
        _, kwargs = mock_flow.call_args
        assert mock_flow.call_args.args[0] == "appliance.example.com"
        assert kwargs["on_device_code"] is callback
        assert kwargs["scope"] == "custom-scope"
        assert kwargs["client_id"] == "cid"
        assert kwargs["polling_interval"] == 8
        assert kwargs["verify"] is False
        assert kwargs["api_version"] == "v4"

    async def test_async_authenticate_delegates_to_flow(self) -> None:
        from pysafeguard import async_device_code as adc

        callback = MagicMock()
        auth = DeviceCodeAuth(callback, scope="custom-scope", client_id="cid")
        client = MagicMock()
        client.host = "appliance.example.com"
        client.verify = False
        client.api_version = "v4"

        with patch.object(adc, "async_get_device_code_token", new=AsyncMock(return_value="user-token")) as mock_flow:
            result = await auth.async_authenticate(client)

        assert result == "user-token"
        _, kwargs = mock_flow.call_args
        assert kwargs["on_device_code"] is callback
        assert kwargs["scope"] == "custom-scope"
        assert kwargs["client_id"] == "cid"
