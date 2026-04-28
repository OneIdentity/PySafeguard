"""PySafeguard — Python SDK for One Identity Safeguard Web API."""

# Client
from .async_client import AsyncSafeguardClient as AsyncSafeguardClient
from .client import SafeguardClient as SafeguardClient

# Auth strategies
from .auth import Auth as Auth
from .auth import CertificateAuth as CertificateAuth
from .auth import PasswordAuth as PasswordAuth
from .auth import PkceAuth as PkceAuth
from .auth import TokenAuth as TokenAuth

# Errors
from .errors import ApiError as ApiError
from .errors import AuthenticationError as AuthenticationError
from .errors import AuthorizationError as AuthorizationError
from .errors import NotFoundError as NotFoundError
from .errors import SafeguardError as SafeguardError
from .errors import TransportError as TransportError

# Enums
from .data_types import A2AType as A2AType
from .data_types import HttpMethod as HttpMethod
from .data_types import Service as Service
from .data_types import SshKeyFormat as SshKeyFormat

# A2A
from .a2a import A2AContext as A2AContext
from .async_a2a import AsyncA2AContext as AsyncA2AContext

# Events
from .event import EventHandlerRegistry as EventHandlerRegistry
from .event import EventListenerState as EventListenerState
from .event import PersistentSafeguardEventListener as PersistentSafeguardEventListener
from .event import SafeguardEventHandler as SafeguardEventHandler
from .event import SafeguardEventListener as SafeguardEventListener
from .event import SafeguardStateCallback as SafeguardStateCallback

# Types
from .hidden_string import HiddenString as HiddenString

__all__ = [
    # Client
    "SafeguardClient",
    "AsyncSafeguardClient",
    # Auth
    "Auth",
    "PasswordAuth",
    "CertificateAuth",
    "TokenAuth",
    "PkceAuth",
    # Errors
    "SafeguardError",
    "ApiError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "TransportError",
    # Enums
    "Service",
    "HttpMethod",
    "A2AType",
    "SshKeyFormat",
    # A2A
    "A2AContext",
    "AsyncA2AContext",
    # Events
    "SafeguardEventListener",
    "PersistentSafeguardEventListener",
    "EventHandlerRegistry",
    "EventListenerState",
    "SafeguardEventHandler",
    "SafeguardStateCallback",
    # Types
    "HiddenString",
]
