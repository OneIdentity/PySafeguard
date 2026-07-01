# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

from __future__ import annotations

import enum
import sys
from dataclasses import dataclass

if sys.version_info < (3, 11):

    class StrEnum(str, enum.Enum):
        pass
else:
    from enum import StrEnum


class Service(StrEnum):
    CORE = "service/core"
    APPLIANCE = "service/appliance"
    NOTIFICATION = "service/notification"
    A2A = "service/a2a"
    EVENT = "service/event"
    RSTS = "RSTS"


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"


class A2AType(StrEnum):
    PASSWORD = "password"
    PRIVATEKEY = "privatekey"
    APIKEYSECRET = "apikey"


class SshKeyFormat(StrEnum):
    OPENSSH = "openssh"
    SSH2 = "ssh2"
    PUTTY = "putty"


# Legacy aliases — deprecated in v8.0, will be removed in a future version.
Services = Service
HttpMethods = HttpMethod
A2ATypes = A2AType
SshKeyFormats = SshKeyFormat


@dataclass(frozen=True)
class DeviceCodeInfo:
    """Display information for an OAuth 2.0 Device Authorization Grant (RFC 8628).

    An instance is handed to the caller-supplied ``on_device_code`` callback so
    the caller can present the verification URL and user code to the end user.
    The library performs no display I/O of its own and never opens a browser.

    The raw ``device_code`` is intentionally **not** exposed here; the SDK keeps
    it internal and owns the polling loop.

    :ivar user_code: The code the user enters at the verification URL.
    :ivar verification_uri: The URL the user visits to authorize the device.
    :ivar verification_uri_complete: The verification URL with the user code
        pre-filled, suitable for display or QR encoding.
    :ivar expires_in: Lifetime in seconds of the device code and user code.
    :ivar interval: Minimum number of seconds to wait between polling requests.
    """

    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int

    @classmethod
    def from_device_login(cls, data: object, *, default_interval: int) -> DeviceCodeInfo:
        """Build a :class:`DeviceCodeInfo` from an rSTS ``DeviceLogin`` JSON body.

        :param data: Parsed JSON object returned by ``POST /RSTS/oauth2/DeviceLogin``.
        :param default_interval: Polling interval used when the response omits ``interval``.
        :returns: A validated :class:`DeviceCodeInfo` containing only display fields.
        :raises SafeguardError: If required display fields are missing or malformed.
        """
        from .errors import SafeguardError

        if not isinstance(data, dict):
            raise SafeguardError("Unexpected response from RSTS DeviceLogin endpoint: expected a JSON object")

        user_code = data.get("user_code")
        if not isinstance(user_code, str) or not user_code:
            raise SafeguardError("RSTS DeviceLogin response is missing the 'user_code' field")

        verification_uri = data.get("verification_uri")
        if not isinstance(verification_uri, str) or not verification_uri:
            raise SafeguardError("RSTS DeviceLogin response is missing the 'verification_uri' field")

        verification_uri_complete = data.get("verification_uri_complete")
        if not isinstance(verification_uri_complete, str) or not verification_uri_complete:
            raise SafeguardError("RSTS DeviceLogin response is missing the 'verification_uri_complete' field")

        expires_in = data.get("expires_in")
        if not isinstance(expires_in, int) or isinstance(expires_in, bool):
            raise SafeguardError("RSTS DeviceLogin response is missing an integer 'expires_in' field")

        interval = data.get("interval", default_interval)
        if not isinstance(interval, int) or isinstance(interval, bool):
            raise SafeguardError("RSTS DeviceLogin response contains a non-integer 'interval' field")

        return cls(
            user_code=user_code,
            verification_uri=verification_uri,
            verification_uri_complete=verification_uri_complete,
            expires_in=expires_in,
            interval=interval,
        )
