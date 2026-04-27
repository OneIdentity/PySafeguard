# AGENTS.md -- PySafeguard

Python SDK for the One Identity Safeguard Web API. Published as a package on
[PyPI](https://pypi.org/project/pysafeguard/).

Requires Python ≥ 3.10. Dependencies: requests, truststore. Optional extras:
`async` (aiohttp), `signalr` (signalrcore).

The .NET counterpart of this SDK is
[SafeguardDotNet](https://github.com/OneIdentity/SafeguardDotNet). Feature
parity with SafeguardDotNet is a long-term goal. Refer to SafeguardDotNet's
codebase and AGENTS.md for guidance on Safeguard API concepts, authentication
flows, and architecture patterns that should be mirrored in Python.

## Project structure

```
PySafeguard/
|-- src/pysafeguard/                # SDK package
|   |-- __init__.py                 # Public API: PySafeguardConnection, SignalR helpers
|   |-- connection.py               # Sync Connection class (requests-based)
|   |-- async_connection.py         # Async AsyncConnection class (aiohttp-based)
|   |-- data_types.py               # Enums: Services, HttpMethods, A2ATypes, SshKeyFormats
|   |-- exceptions.py               # SafeguardException base, WebRequestError, AsyncWebRequestError
|   |-- pkce.py                     # PKCE non-interactive login (rSTS multi-step flow)
|   |-- hidden_string.py             # HiddenString wrapper for sensitive values
|   |-- utility.py                  # URL assembly, token extraction helpers
|   `-- py.typed                    # PEP 561 marker for typed package
|
|-- samples/                        # Example scripts
|   |-- PasswordExample.py          # Username/password authentication
|   |-- PasswordExternalExample.py  # External provider authentication
|   |-- CertificateExample.py       # Client certificate authentication
|   |-- CertificateExternalExample.py # Certificate with external provider
|   |-- AnonymousExample.py         # Unauthenticated connection
|   |-- NewUserExample.py           # Create user and set password
|   |-- A2APasswordExample.py       # A2A password retrieval
|   |-- A2APrivateKeyExample.py     # A2A private key retrieval
|   |-- A2AApiKeySecretExample.py   # A2A API key secret retrieval
|   `-- SignalRExample.py           # SignalR event registration
|
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
pass `mypy --strict` without errors. Key mypy settings:
- `disallow_untyped_defs = True` — every function must have type annotations
- `strict_bytes = True`, `strict_equality = True`
- `warn_return_any = True`, `warn_unreachable = True`
- `ignore_missing_imports = True` — third-party stubs may not always be available

Ruff enforces a line length of 160 characters.

## Testing against a live appliance

This SDK interacts with a live Safeguard appliance API. **There are no
mock/unit tests.** The `samples/` directory contains example scripts that
require a live appliance. Running samples against a live appliance is the
primary way to validate changes.

### Asking the user for appliance access

**If you are making non-trivial code changes, ask the user whether they have
access to a live Safeguard appliance for testing.** If they do, ask for:

1. **Appliance address** (IP or hostname of a Safeguard for Privileged Passwords appliance)
2. **Admin username** (typically `Admin`)
3. **Admin password**
4. **CA certificate path** (path to PEM file for TLS verification, or `False` to disable)

This is not required for documentation or minor fixes, but it is **strongly
encouraged** for any change that touches authentication, API calls, connection
logic, or event handling.

### Running a sample to validate

```bash
cd samples/
python PasswordExample.py
```

Each sample will prompt for or require connection details. Review the sample
source to understand required arguments.

## Architecture

### Entry points

- **`PySafeguardConnection`** (in `__init__.py`) — The primary public class.
  Inherits from `Connection` and adds SignalR event registration methods.
  Users import everything from `pysafeguard`:
  ```python
  from pysafeguard import *
  ```

- **`AsyncConnection`** (in `async_connection.py`) — Async variant using
  `aiohttp`. Mirrors the sync `Connection` API but all I/O methods are
  `async`/`await`.

### Connection classes

| Class | Module | HTTP library | Description |
|---|---|---|---|
| `Connection` | `connection.py` | `requests` | Sync base connection. Auth, invoke, token management. |
| `AsyncConnection` | `async_connection.py` | `aiohttp` | Async mirror of Connection. |
| `PySafeguardConnection` | `__init__.py` | — | Extends `Connection` with SignalR support. |

### Authentication flow

1. Call `connect_password()`, `connect_certificate()`, or `connect_token()`
2. Password/certificate methods POST to `RSTS/oauth2/token` (Resource Owner Grant)
3. The rSTS `access_token` is exchanged for a Safeguard `UserToken` via `Core/Token/LoginResponse`
4. The `UserToken` is stored and sent as `Authorization: Bearer <token>` on subsequent calls
5. `invoke()` makes HTTP requests against the Safeguard API services

**Note:** Resource Owner Grant (ROG) is disabled by default on newer Safeguard
appliances. Password authentication may fail with a 400 error. PySafeguard does
not yet support PKCE authentication — this is a feature gap compared to
SafeguardDotNet.

### Safeguard API services

| Service enum | URL path | Description |
|---|---|---|
| `Services.CORE` | `service/core` | Primary API: assets, users, policies, access requests |
| `Services.APPLIANCE` | `service/appliance` | Appliance management: networking, diagnostics, backups |
| `Services.NOTIFICATION` | `service/notification` | Anonymous status and notification endpoints |
| `Services.A2A` | `service/a2a` | Application-to-Application credential retrieval |
| `Services.EVENT` | `service/event` | SignalR event streaming |
| `Services.RSTS` | `RSTS` | Embedded secure token service (authentication) |

The default API version is **v4**.

### A2A (Application-to-Application)

`a2a_get_credential()` is a class method on both `Connection` and
`AsyncConnection`. It uses client certificate authentication with an API key
header (`Authorization: A2A <apiKey>`) to retrieve credentials without going
through the standard user token flow. Supports password, private key, and API
key secret retrieval.

### PKCE non-interactive login

`pkce.py` implements the full rSTS PKCE authentication flow without a browser.
This is the **recommended** authentication method on newer appliances where
Resource Owner Grant (ROG) is disabled by default.

The flow drives the rSTS login controller through multiple steps:
1. **Step 1 (Init)**: Provider initialization with CSRF token
2. **Step 3 (PrimaryAuth)**: Username/password submission
3. **Step 7 (SecondaryInit)** + **Step 5 (SecondaryAuth)**: MFA if required
4. **Step 6 (GenerateClaims)**: Authorization code extraction
5. **Token exchange**: Authorization code → rSTS token → Safeguard user token

Key implementation details:
- CSRF token: 32 random bytes → base64url, set as cookie on `/RSTS` path
- Code verifier: 60 random bytes → base64url
- Code challenge: SHA256(ASCII(verifier)) → base64url
- Base64url: standard base64 with `+`→`-`, `/`→`_`, padding stripped
- Provider resolution: 3-level match (exact RstsProviderId → exact Name → substring)
- 203 from rSTS = challenge/error (handled per-step, not globally)
- JSON responses parsed opportunistically (non-JSON means no secondary auth)

### Connect factory functions

Module-level convenience functions in `__init__.py` for creating connections:
- `connect_pkce(appliance, provider, username, password, ...)` — PKCE flow (recommended)
- `connect_persistent(appliance, provider, username, password, ...)` — PKCE with auto-refresh
- `connect_password(appliance, username, password, ...)` — ROG password auth
- `connect_certificate(appliance, cert_file, key_file, ...)` — client certificate
- `connect_token(appliance, token, ...)` — existing Safeguard API token
- `connect_anonymous(appliance, ...)` — unauthenticated access

All return a `PySafeguardConnection` (or `Connection` for `connect_pkce`/`connect_persistent`).

### Token refresh and lifecycle

- **Credential storage**: `connect_password()`, `connect_certificate()`, and
  `connect_pkce()` store authentication credentials internally (in frozen
  dataclasses with `eq=False`) so that tokens can be refreshed. Sensitive fields
  (passwords, TOTP codes) are wrapped in `HiddenString` (see below).
- **`_replace_auth_credential()`** swaps credentials and disposes secrets from
  the previous credential via `HiddenString.dispose()`.
- **`_set_user_token()`** is the internal token setter that preserves refresh
  credentials. The public `connect_token()` clears them (bare tokens can't refresh).
- **`refresh_access_token()`** re-authenticates using stored credentials. Raises
  `SafeguardException` if no credentials are available (e.g. `connect_token()`).
  PKCE connections requiring MFA cannot be refreshed (one-time passwords).
- **`logout()`** POSTs to `Token/Logout` (best-effort), then clears the local
  token. Does **not** dispose credentials (so `refresh_access_token()` still works).
- **Auto-refresh**: When `_auto_refresh` is `True`, `invoke()` checks
  `get_remaining_token_lifetime()` before each API call (excluding RSTS and
  APPLIANCE service calls to avoid recursion) and refreshes if expired.
  `connect_persistent()` enables this flag.

### HiddenString

`HiddenString` (in `hidden_string.py`) is a best-effort wrapper for sensitive
values, inspired by .NET's `SecureString`. It provides:

- **`bytearray` storage** — mutable, so memory can be explicitly zeroed
- **`dispose()`** — zeros the buffer and marks the string as disposed
- **`get_value()`** — explicit access with `RuntimeError` after disposal
- **`repr()`/`str()` protection** — always returns `***`
- **Serialization blocking** — `__reduce_ex__`, `__copy__`, `__deepcopy__` all raise `TypeError`

**Limitations** (documented in module docstring): Python cannot encrypt memory or
guarantee transient copies are scrubbed. The original `str` argument, `get_value()`
return values, and HTTP library copies exist briefly in memory. This minimizes
the window and surface area of exposure, not eliminates it.

### SignalR event listeners

`PySafeguardConnection` provides two static methods for SignalR:
- `register_signalr_username()` — authenticate with username/password, then listen
- `register_signalr_certificate()` — authenticate with certificate, then listen

Both use the `signalrcore` library. SignalR connects to `service/event/signalr`
and listens for `ReceiveMessage` and `NotifyEventAsync` events.

### Error handling

- **`SafeguardException`** (in `exceptions.py`) — Base exception for all SDK errors.
  Carries `status_code`, `error_code`, `error_message`, `response` (raw body),
  and `has_response`. Auto-parses JSON error bodies (`Code`, `Message` fields
  from the Safeguard API, and SPS-style `error` fields).
- **`WebRequestError(SafeguardException)`** — raised on non-200 responses in
  sync code. Contains the `Response` object via `req` attribute and a formatted
  `message` string.
- **`AsyncWebRequestError(SafeguardException)`** — async equivalent, wraps
  `aiohttp.ClientResponse`.
- `ValueError` is raised for validation errors (missing API key, missing cert).
- `SafeguardException` is raised for domain errors (provider not found).

## Code conventions

### Type annotations

All functions must have complete type annotations. The project uses `mypy` in
strict mode. Use `typing.cast()` when narrowing types from JSON responses.

For Python 3.10 compatibility:
- `StrEnum` is polyfilled in `data_types.py` for Python < 3.11
- `LiteralString` is imported from `typing_extensions` for Python < 3.11

### Docstrings

Use reStructuredText-style docstrings (`:param name:`, `:returns:`). Every
public method should have a docstring.

### Naming conventions

- Classes: PascalCase (`Connection`, `PySafeguardConnection`)
- Methods/functions: snake_case (`connect_password`, `assemble_url`)
- Instance attributes: camelCase where matching the Safeguard API
  (`UserToken`, `apiVersion`) — this is a legacy convention from the original
  codebase
- Enums: UPPER_CASE values (`HttpMethods.GET`, `Services.CORE`)
- Private methods: double underscore prefix (`__connect`, `__execute_web_request`)

### Import style

Use explicit imports from submodules. The `__init__.py` re-exports the public
API. Type-only imports use `typing.cast()` rather than `TYPE_CHECKING` guards.

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

## Feature gaps vs SafeguardDotNet

PySafeguard is a simpler SDK compared to SafeguardDotNet. Key features present
in SafeguardDotNet but missing from PySafeguard include:

- **PKCE authentication** — SafeguardDotNet has full PKCE non-interactive login;
  PySafeguard only supports Resource Owner Grant (which is disabled by default
  on newer appliances)
- **Persistent connections** — auto-refreshing token management
  (`PersistentSafeguardConnection`)
- **Persistent event listeners** — auto-reconnecting SignalR with exponential
  backoff
- **Custom exception type** — SafeguardDotNet's `SafeguardDotNetException`
  carries HTTP status, error code, and parsed error message
- **Management service connection** — for disaster recovery and support
  operations
- **SPS integration** — Safeguard for Privileged Sessions connection joining
- **Streaming support** — streaming API responses
- **MFA/TOTP support** — secondary authentication factor handling
- **Access request brokering** — A2A access request broker functionality

When adding new features, refer to the SafeguardDotNet implementation for
design patterns and API contract details.
