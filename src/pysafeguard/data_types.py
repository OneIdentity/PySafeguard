# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

import enum
import sys

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
