import sys
from collections.abc import Mapping
from urllib.parse import urlencode, urlunparse

if sys.version_info < (3, 11):
    from typing_extensions import LiteralString as LiteralString
else:
    from typing import LiteralString as LiteralString


def assemble_path(*args: str | None) -> str:
    return "/".join(arg.strip("/") for arg in args if arg is not None)


def assemble_url(netloc: str = "", path: str = "", query: Mapping[str, str] = {}, fragment: str = "", scheme: LiteralString = "https") -> str:
    return urlunparse((scheme, netloc, path, "", urlencode(query, True), fragment))
