import enum
import sys

if sys.version_info < (3, 11):

    class StrEnum(str, enum.Enum):
        pass
else:
    from enum import StrEnum


class Services(StrEnum):
    CORE = "service/core"
    APPLIANCE = "service/appliance"
    NOTIFICATION = "service/notification"
    A2A = "service/a2a"
    EVENT = "service/event"
    RSTS = "RSTS"


class HttpMethods(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"


class A2ATypes(StrEnum):
    PASSWORD = "password"
    PRIVATEKEY = "privatekey"
    APIKEYSECRET = "apikey"


class SshKeyFormats(StrEnum):
    OPENSSH = "openssh"
    SSH2 = "ssh2"
    PUTTY = "putty"
