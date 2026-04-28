# AGENTS.md -- PySafeguard

Python SDK for the One Identity Safeguard Web API. Published as a package on
[PyPI](https://pypi.org/project/pysafeguard/).

Requires Python ≥ 3.10. Dependencies: requests, truststore (and
typing\_extensions on Python < 3.11). Optional extras: `async` (aiohttp),
`signalr` (signalrcore).

The .NET counterpart of this SDK is
[SafeguardDotNet](https://github.com/OneIdentity/SafeguardDotNet). Refer to
SafeguardDotNet's codebase and AGENTS.md for guidance on Safeguard API concepts
and authentication flows.

## Project structure

```
PySafeguard/
|-- src/pysafeguard/                # SDK package
|   |-- __init__.py                 # Public API with __all__ and async lazy imports
|   |-- client.py                   # SafeguardClient (sync, requests-based)
|   |-- async_client.py             # AsyncSafeguardClient (async, aiohttp-based)
|   |-- auth.py                     # Auth protocol + PasswordAuth, CertificateAuth, PkceAuth, TokenAuth
|   |-- errors.py                   # SafeguardError hierarchy (ApiError, AuthenticationError, etc.)
|   |-- data_types.py               # Enums: Service, HttpMethod, A2AType, SshKeyFormat
|   |-- event.py                    # SafeguardEventListener, PersistentSafeguardEventListener
|   |-- a2a.py                      # A2AContext (sync)
|   |-- async_a2a.py                # AsyncA2AContext (async)
|   |-- hidden_string.py            # HiddenString wrapper for sensitive values
|   |-- pkce.py                     # Sync PKCE non-interactive login (internal)
|   |-- async_pkce.py               # Async PKCE non-interactive login (internal)
|   |-- utility.py                  # URL assembly, token extraction helpers
|   `-- py.typed                    # PEP 561 marker for typed package
|
|-- tests/                          # Unit and integration tests
|   |-- conftest.py                 # Shared fixtures, auto-skip integration when SPP_HOST unset
|   |-- test_auth.py                # Auth strategy tests
|   |-- test_client_new.py          # SafeguardClient init/lifecycle tests
|   |-- test_client_request_logic.py # SafeguardClient request tests (mocked HTTP)
|   |-- test_async_client_new.py    # AsyncSafeguardClient tests
|   |-- test_safeguard_errors.py    # Error hierarchy tests
|   |-- test_public_api.py          # Export surface verification
|   |-- test_event.py               # Event listener tests
|   |-- test_a2a.py                 # A2AContext tests
|   |-- test_hidden_string.py       # HiddenString tests
|   |-- test_data_types.py          # Enum tests
|   |-- test_pkce_helpers.py        # PKCE flow tests
|   |-- test_utility.py             # Utility function tests
|   `-- integration/                # Live-appliance integration tests
|       |-- conftest.py             # Preflight fixture: enables ROG via PKCE if disabled
|       |-- test_auth_sync.py       # Sync auth flow tests (password, cert, PKCE)
|       |-- test_auth_async.py      # Async auth flow tests
|       |-- test_invoke_sync.py     # Sync API invocation tests
|       |-- test_invoke_async.py    # Async API invocation tests
|       |-- test_user_crud_sync.py  # Sync user CRUD operations
|       |-- test_user_crud_async.py # Async user CRUD operations
|       |-- test_token_sync.py      # Sync token lifecycle tests
|       |-- test_token_async.py     # Async token lifecycle tests
|       |-- test_client_features.py # Client feature tests (provider lookup, etc.)
|       |-- test_streaming.py       # Stream/download/upload tests
|       |-- test_a2a.py             # A2A credential retrieval tests
|       |-- test_event_listener.py  # SignalR event listener tests
|       |-- test_persistent_listener_factory.py # Persistent listener factory tests
|       |-- test_certificate_auth.py # Certificate auth-specific tests
|       |-- test_pkce_auth.py       # PKCE auth-specific tests
|       |-- test_factories.py       # Factory method tests
|       `-- test_anonymous.py       # Anonymous/unauthenticated access tests
|
|-- samples/                        # Example scripts (see Samples section below)
|   |-- PasswordExample.py          # PasswordAuth with local provider
|   |-- PasswordExternalExample.py  # PasswordAuth with external provider
|   |-- CertificateExample.py       # CertificateAuth
|   |-- CertificateExternalExample.py # CertificateAuth with external provider
|   |-- PkceExample.py              # PkceAuth flow
|   |-- AnonymousExample.py         # Unauthenticated access (Service.NOTIFICATION)
|   |-- NewUserExample.py           # User creation via CORE API
|   |-- SignalRExample.py           # One-shot SignalR event listener
|   |-- PersistentSignalRExample.py # Auto-reconnecting event listener
|   |-- A2APasswordExample.py       # A2A password retrieval
|   |-- A2APrivateKeyExample.py     # A2A private key retrieval
|   `-- A2AApiKeySecretExample.py   # A2A API key secret retrieval
|
|-- pipeline-templates/             # Azure Pipelines shared templates
|   |-- build-steps.yml             # Build, lint, test, package steps
|   `-- global-variables.yml        # Pipeline variable definitions
|-- pyproject.toml                  # Project metadata, dependencies (Poetry build backend)
|-- ruff.toml                       # Ruff linter/formatter configuration
|-- mypy.ini                        # Mypy strict type checking configuration
|-- azure-pipelines.yml             # CI/CD: build with Poetry, publish to PyPI on tag
|-- versionnumber.ps1               # PowerShell script for CI version stamping
`-- README.md                       # User-facing documentation and usage examples
```

## Setup and build commands

The project uses [Poetry](https://python-poetry.org/) as its build backend.

```bash
# Install Poetry (if not already installed)
pip install poetry

# Install all dependencies (including dev and optional extras)
poetry install --all-extras

# Build the distribution (sdist + wheel)
poetry build
```

## Linting and type checking

```bash
# Lint with ruff (line length: 160)
ruff check src/

# Format check with ruff
ruff format --check src/

# Type check with mypy (strict mode enabled)
mypy src/
```

Mypy is configured in strict mode with all strict flags enabled. All code must
pass `mypy --strict` without errors.

Ruff enforces a line length of 160 characters.

## Testing

```bash
# Run unit tests (no live appliance required)
python -m pytest tests/ -m "not integration"

# Run integration tests (requires live appliance)
SPP_HOST=<host> SPP_USERNAME=<user> SPP_PASSWORD=<pass> python -m pytest tests/ -m integration
```

The test suite uses `pytest-asyncio` with `asyncio_mode = "auto"` (configured
in `pyproject.toml`), so async test functions run automatically without
`@pytest.mark.asyncio`.

### Testing against a live appliance

Integration tests interact with a real Safeguard appliance. **If making
non-trivial changes to authentication, API calls, or event handling, ask the
user for appliance access** and request: appliance address, admin username,
admin password, and CA certificate path (or `False` to disable TLS verification).

Environment variables for integration tests:

| Variable | Required | Default | Description |
|---|---|---|---|
| `SPP_HOST` | **Yes** | — | Appliance hostname or IP. Tests auto-skip when unset. |
| `SPP_USERNAME` | No | `Admin` | Safeguard user for authentication. |
| `SPP_PASSWORD` | **Yes** | — | Password for the Safeguard user. |
| `SPP_CA_FILE` | No | — | Path to CA certificate file. Omit to disable TLS verification. |

## Architecture

### Client classes

| Class | Module | HTTP library | Description |
|---|---|---|---|
| `SafeguardClient` | `client.py` | `requests` | Primary sync client. Side-effect-free constructor. |
| `AsyncSafeguardClient` | `async_client.py` | `aiohttp` | Async mirror of SafeguardClient. |

### Authentication strategies

Auth objects are passed to the client constructor. Each implements the `Auth`
protocol (`auth.py`) with `authenticate()`, `refresh()`, `can_refresh`, and
async variants. The `Auth` protocol itself is exported in `__all__` and can be
used for type annotations.

| Strategy | Module | Description |
|---|---|---|
| `PasswordAuth` | `auth.py` | Username/password (Resource Owner Grant) |
| `CertificateAuth` | `auth.py` | Client certificate authentication |
| `PkceAuth` | `auth.py` | PKCE non-interactive browser flow (recommended) |
| `TokenAuth` | `auth.py` | Pre-existing bearer token (no refresh) |

Secret fields (passwords, tokens) are auto-wrapped in `HiddenString`.

### Usage pattern

```python
from pysafeguard import SafeguardClient, PasswordAuth, Service

# Context manager auto-logs in and out
with SafeguardClient("appliance.example.com",
                     auth=PasswordAuth("local", "admin", "secret"),
                     verify=False) as client:
    users = client.get(Service.CORE, "Users").json()
    client.post(Service.CORE, "Users", json={"Name": "NewUser"})
```

### Authentication flow

1. Construct `SafeguardClient` with an `Auth` object (no network I/O)
2. Call `client.login()` (or use context manager which calls it automatically)
3. Auth object POSTs to `RSTS/oauth2/token` for an rSTS access token
4. rSTS access token is exchanged for a Safeguard `UserToken` via `Core/Token/LoginResponse`
5. `UserToken` is sent as `Authorization: Bearer <token>` on subsequent requests
6. `client.logout()` invalidates the token on the appliance

### HTTP methods

```python
client.get(service, endpoint, *, params=None, headers=None, host=None, cert=None, api_version=None)
client.post(service, endpoint, *, json=None, data=None, params=None, headers=None, host=None, cert=None, api_version=None)
client.put(service, endpoint, *, json=None, data=None, params=None, headers=None, host=None, cert=None, api_version=None)
client.delete(service, endpoint, *, params=None, headers=None, host=None, cert=None, api_version=None)
client.request(method, service, endpoint, *, ...)  # Low-level escape hatch
```

- `json=` for dict/list bodies (auto-sets content-type)
- `data=` for raw string bodies
- `params=` for query parameters
- `headers=` for additional headers (merged with defaults)
- `host=` to override the target host (useful for clusters)
- `cert=` for client certificate as `(cert_file, key_file)` tuple
- `api_version=` to override the API version for a single request

### Streaming

```python
client.stream(method, service, endpoint, **kwargs)   # Returns un-consumed response
client.download(service, endpoint, file_path, **kwargs)  # Stream to file
client.upload(service, endpoint, file_or_stream, **kwargs)  # Upload file/bytes
```

### Safeguard API services

| Enum | URL path | Description |
|---|---|---|
| `Service.CORE` | `service/core` | Primary API: assets, users, policies, access requests |
| `Service.APPLIANCE` | `service/appliance` | Appliance management: networking, diagnostics, backups |
| `Service.NOTIFICATION` | `service/notification` | Anonymous status and notification endpoints |
| `Service.A2A` | `service/a2a` | Application-to-Application credential retrieval |
| `Service.EVENT` | `service/event` | SignalR event streaming |
| `Service.RSTS` | `RSTS` | Embedded secure token service (authentication) |

The default API version is **v4**.

### Error hierarchy

```
SafeguardError (base)
├── ApiError (HTTP error responses)
│   ├── AuthenticationError (401)
│   ├── AuthorizationError (403)
│   └── NotFoundError (404)
└── TransportError (network/connection failures)
```

`ApiError.from_response(resp)` auto-maps status codes to subclasses.
All errors carry `status_code`, `error_code`, `error_message`, `response_body`.

### A2A (Application-to-Application)

`A2AContext` and `AsyncA2AContext` use client certificate authentication with
an API key header (`Authorization: A2A <apiKey>`) to retrieve credentials.
Supports password, private key, and API key secret retrieval.

For one-shot operations without a context manager, use the static convenience
methods:

```python
password = A2AContext.quick_retrieve_password(host, api_key, cert_file, key_file)
private_key = A2AContext.quick_retrieve_private_key(host, api_key, cert_file, key_file)
```

### Event listeners

- `SafeguardEventListener` — one-shot SignalR listener with token auth
- `PersistentSafeguardEventListener` — auto-reconnecting listener that
  re-authenticates on disconnect

Created via `client.get_event_listener()` / `client.get_persistent_event_listener()`.

Related public types (all exported from `__init__.py`):

- `EventHandlerRegistry` — container for registered event handlers
- `EventListenerState` — enum: `STARTING`, `CONNECTED`, `DISCONNECTED`,
  `RECONNECTING`, `STOPPED`
- `SafeguardEventHandler` — callback type alias: `(event_name, event_body) -> None`
- `SafeguardStateCallback` — callback type alias: `(EventListenerState) -> None`

### PKCE non-interactive login

`pkce.py` (internal) implements the full rSTS PKCE authentication flow without
a browser. This is the **recommended** method on newer appliances where Resource
Owner Grant (ROG) is disabled by default. The flow is exposed to users via `PkceAuth`.

### HiddenString

`HiddenString` wraps sensitive values to prevent casual exposure in logs, repr,
and debugger output. Uses `bytearray` storage for explicit zeroing on disposal.
Supports context manager (`with HiddenString(...) as s:`) for scoped disposal,
`__len__`, `__eq__`, `__bool__`, and blocks pickling/copying.

### Token refresh and lifecycle

- `client.refresh_access_token()` re-authenticates using the stored auth object
- `client.token_lifetime_remaining` (property) checks remaining token lifetime
- `auto_refresh=True` on construction enables automatic refresh before each request
- `client.logout()` POSTs to `Token/Logout` then clears the local token

### Async lazy imports

`AsyncSafeguardClient` and `AsyncA2AContext` are lazily imported via
`__getattr__` in `__init__.py` so that `import pysafeguard` works without the
`[async]` extra (aiohttp) installed. On first access, if aiohttp is missing, a
helpful `ImportError` is raised directing the user to install
`pysafeguard[async]`.

## Code conventions

### Type annotations

All functions must have complete type annotations. The project uses `mypy` in
strict mode. Use `typing.cast()` when narrowing types from JSON responses.

`data_types.py` includes a `StrEnum` compatibility shim for Python 3.10 (before
`enum.StrEnum` was added in 3.11). Similarly, `utility.py` conditionally imports
`LiteralString` from `typing_extensions` on Python < 3.11.

### Naming conventions

- Classes: PascalCase (`SafeguardClient`, `PasswordAuth`)
- Methods/functions: snake_case (`get_provider_id`, `assemble_url`)
- Instance attributes: snake_case (`user_token`, `api_version`, `is_authenticated`)
- Enums: Singular names with UPPER_CASE values (`Service.CORE`, `HttpMethod.GET`)
- Private attributes: single underscore prefix (`_user_token`, `_session`)

### Docstrings

Use reStructuredText-style docstrings (`:param name:`, `:returns:`). Every
public method should have a docstring.

### Design principles

1. **Side-effect-free constructors** — no network I/O in `__init__`
2. **Auth as strategy objects** — not factory functions or instance methods
3. **Keyword-only args** — after the first 1-2 positional params
4. **No mutable defaults** — use `None` everywhere
5. **snake_case everything** — no exceptions
6. **Explicit `json`/`data` split** — no magic body inference
7. **Clean `__all__`** — typed, intentional public surface
8. **Secret protection** — HiddenString/repr=False on all credential fields

## Deprecations (v8.0)

The following are deprecated and will be removed in a future version:

- **Plural enum aliases** (`data_types.py`): `Services` → use `Service`,
  `HttpMethods` → use `HttpMethod`, `A2ATypes` → use `A2AType`,
  `SshKeyFormats` → use `SshKeyFormat`.
- **`HiddenString.get_value()`** (`hidden_string.py`): Use the `.value`
  property instead.

## Versioning and release

The version is set in `pyproject.toml` (`version = "X.Y.Z"`). The CI pipeline
(`azure-pipelines.yml`) delegates version stamping to
`pipeline-templates/build-steps.yml`, which calls the PowerShell script
`versionnumber.ps1`. This script computes the package version from the Git tag
name and build ID.

Releases are published to PyPI automatically when a Git tag is pushed. The
pipeline uses `twine` to upload via the `pypiOneIdentity` service connection.

**Do not change the version in `pyproject.toml` manually for releases.** The
CI pipeline handles version stamping from the Git tag.
