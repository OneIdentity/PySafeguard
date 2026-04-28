# AGENTS.md -- PySafeguard

Python SDK for the One Identity Safeguard Web API. Published as a package on
[PyPI](https://pypi.org/project/pysafeguard/).

Requires Python ≥ 3.10. Dependencies: requests, truststore. Optional extras:
`async` (aiohttp), `signalr` (signalrcore).

The .NET counterpart of this SDK is
[SafeguardDotNet](https://github.com/OneIdentity/SafeguardDotNet). Refer to
SafeguardDotNet's codebase and AGENTS.md for guidance on Safeguard API concepts
and authentication flows.

## Project structure

```
PySafeguard/
|-- src/pysafeguard/                # SDK package
|   |-- __init__.py                 # Public API with __all__
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
|
|-- samples/                        # Example scripts
|-- pyproject.toml                  # Project metadata, dependencies (Poetry build backend)
|-- ruff.toml                       # Ruff linter/formatter configuration
|-- mypy.ini                        # Mypy strict type checking configuration
|-- azure-pipelines.yml             # CI/CD: build with Poetry, publish to PyPI on tag
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

### Testing against a live appliance

Integration tests interact with a real Safeguard appliance. **If making
non-trivial changes to authentication, API calls, or event handling, ask the
user for appliance access** and request: appliance address, admin username,
admin password, and CA certificate path (or `False` to disable TLS verification).

## Architecture

### Client classes

| Class | Module | HTTP library | Description |
|---|---|---|---|
| `SafeguardClient` | `client.py` | `requests` | Primary sync client. Side-effect-free constructor. |
| `AsyncSafeguardClient` | `async_client.py` | `aiohttp` | Async mirror of SafeguardClient. |

### Authentication strategies

Auth objects are passed to the client constructor. Each implements the `Auth`
protocol with `authenticate()`, `refresh()`, `can_refresh`, and async variants.

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
client.get(service, endpoint, *, params=None, headers=None)
client.post(service, endpoint, *, json=None, data=None, params=None, headers=None)
client.put(service, endpoint, *, json=None, data=None, params=None, headers=None)
client.delete(service, endpoint, *, params=None, headers=None)
client.request(method, service, endpoint, *, ...)  # Low-level escape hatch
```

- `json=` for dict/list bodies (auto-sets content-type)
- `data=` for raw string bodies
- `params=` for query parameters
- `headers=` for additional headers (merged with defaults)

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

### Event listeners

- `SafeguardEventListener` — one-shot SignalR listener with token auth
- `PersistentSafeguardEventListener` — auto-reconnecting listener that
  re-authenticates on disconnect

Created via `client.get_event_listener()` / `client.get_persistent_event_listener()`.

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

## Code conventions

### Type annotations

All functions must have complete type annotations. The project uses `mypy` in
strict mode. Use `typing.cast()` when narrowing types from JSON responses.

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

## Versioning and release

The version is set in `pyproject.toml` (`version = "X.Y.Z"`). The CI pipeline
(`azure-pipelines.yml`) overrides the version from the Git tag name when
building from a tag:

```yaml
poetry version $(build.SourceBranchName)
```

Releases are published to PyPI automatically when a Git tag is pushed. The
pipeline uses `twine` to upload via the `pypiOneIdentity` service connection.

**Do not change the version in `pyproject.toml` manually for releases.** The
CI pipeline handles version stamping from the Git tag.
