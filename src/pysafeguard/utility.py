import sys
from collections.abc import Mapping
from urllib.parse import urlencode, urlunparse

if sys.version_info < (3, 11):
    from typing_extensions import LiteralString as LiteralString
else:
    from typing import LiteralString as LiteralString

JsonType = None | bool | int | float | str | dict[str, "JsonType"] | list["JsonType"]


def assemble_path(*args: str | None) -> str:
    return "/".join(arg.strip("/") for arg in args if arg is not None)


def assemble_url(netloc: str = "", path: str = "", query: Mapping[str, str] = {}, fragment: str = "", scheme: LiteralString = "https") -> str:
    return urlunparse((scheme, netloc, path, "", urlencode(query, True), fragment))


def get_access_token(data: JsonType) -> str:
    if not isinstance(data, dict) or (access_token := data.get("access_token")) is None:
        raise TypeError("expected: JSON object with field `access_token`")
    if not isinstance(access_token, str):
        raise TypeError("expected: `access_token` as a string")
    return access_token


def get_user_token(data: JsonType) -> str:
    if not isinstance(data, dict) or (user_token := data.get("UserToken")) is None:
        raise TypeError("expected: JSON object with field `UserToken`")
    if not isinstance(user_token, str):
        raise TypeError("expected: `UserToken` as a string")
    return user_token
