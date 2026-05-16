# AGENTS.md -- PySafeguard

Python SDK for the One Identity Safeguard Web API. Published on
[PyPI](https://pypi.org/project/pysafeguard/). Requires Python ≥ 3.10.

Dependencies: `requests`, `truststore` (and `typing_extensions` on Python
< 3.11). Optional extras: `async` (aiohttp), `signalr` (signalrcore).

## Project structure

```
PySafeguard/
|-- src/pysafeguard/           # SDK package
|   |-- __init__.py            # Public API (__all__) and async lazy imports
|   |-- client.py              # SafeguardClient (sync, requests-based)
|   |-- async_client.py        # AsyncSafeguardClient (async, aiohttp-based)
|   |-- auth.py                # Auth protocol + PasswordAuth, CertificateAuth, PkceAuth, TokenAuth
|   |-- errors.py              # SafeguardError hierarchy
|   |-- data_types.py          # Enums: Service, HttpMethod, A2AType, SshKeyFormat
|   |-- event.py               # SafeguardEventListener, PersistentSafeguardEventListener
|   |-- a2a.py / async_a2a.py  # A2AContext / AsyncA2AContext
|   |-- hidden_string.py       # HiddenString (sensitive value wrapper)
|   |-- pkce.py / async_pkce.py # PKCE non-interactive login (internal)
|   `-- utility.py             # URL assembly, token extraction helpers
|-- tests/                     # Unit tests (mocked HTTP, no appliance needed)
|   `-- integration/           # Live-appliance integration tests
|-- samples/                   # Example scripts for each auth strategy and feature
|-- pipeline-templates/        # Azure Pipelines shared templates
|-- pyproject.toml             # Poetry build backend, dependencies, pytest config
|-- ruff.toml                  # Ruff linter/formatter (line length: 160)
|-- mypy.ini                   # Mypy strict type checking
`-- azure-pipelines.yml        # CI/CD: build, lint, test, publish to PyPI on tag
```

## Setup and build

```bash
pip install poetry                   # Install Poetry (if needed)
poetry install --all-extras          # Install all deps including dev and optional
poetry build                         # Build sdist + wheel
```

All `poetry run` prefixed commands below assume deps are installed via
`poetry install --all-extras`.

## Linting and type checking

```bash
poetry run ruff check src/                   # Lint (line length: 160)
poetry run ruff format --check src/          # Format check
poetry run mypy src/                         # Type check (strict mode)
```

All code must pass `mypy --strict` without errors. Ruff enforces 160-char lines.

## Testing

```bash
poetry run python -m pytest tests/ -m "not integration"    # Unit tests
poetry run python -m pytest tests/ -m integration           # Integration (live appliance)
```

Uses `pytest-asyncio` with `asyncio_mode = "auto"` — async tests run without
`@pytest.mark.asyncio`. Integration tests auto-skip when `SPP_HOST` is unset.

**For non-trivial auth/API/event changes, ask the user for appliance access.**
See the `testing-guide` skill for environment variables, fixtures, and patterns.

## Architecture

| Class | Module | Description |
|---|---|---|
| `SafeguardClient` | `client.py` | Primary sync client (`requests`) |
| `AsyncSafeguardClient` | `async_client.py` | Async mirror (`aiohttp`) |

### Auth strategies

Auth objects implement the `Auth` protocol (`auth.py`) and are passed to the
client constructor. Secret fields are auto-wrapped in `HiddenString`.

| Strategy | Description |
|---|---|
| `PasswordAuth` | Username/password (Resource Owner Grant) |
| `CertificateAuth` | Client certificate authentication |
| `PkceAuth` | PKCE non-interactive flow (recommended for newer appliances) |
| `TokenAuth` | Pre-existing bearer token (no refresh) |

### Usage pattern

```python
from pysafeguard import SafeguardClient, PasswordAuth, Service

with SafeguardClient("appliance.example.com",
                     auth=PasswordAuth("local", "admin", "secret"),
                     verify=False) as client:
    users = client.get(Service.CORE, "Users").json()
    client.post(Service.CORE, "Users", json={"Name": "NewUser"})
```

### API services

| Enum | URL path | Description |
|---|---|---|
| `Service.CORE` | `service/core` | Users, assets, policies, access requests |
| `Service.APPLIANCE` | `service/appliance` | Appliance management |
| `Service.NOTIFICATION` | `service/notification` | Anonymous status endpoints |
| `Service.A2A` | `service/a2a` | Application-to-Application credentials |
| `Service.EVENT` | `service/event` | SignalR event streaming |
| `Service.RSTS` | `RSTS` | Embedded secure token service |

Default API version: **v4**.

### Error hierarchy

```
SafeguardError
├── ApiError          (HTTP errors; auto-mapped by status code)
│   ├── AuthenticationError (401)
│   ├── AuthorizationError  (403)
│   └── NotFoundError       (404)
└── TransportError    (network/connection failures)
```

## Code conventions

- **Type annotations:** Complete on all functions. `mypy --strict` enforced.
  Use `typing.cast()` for JSON narrowing. `StrEnum` shim in `data_types.py`
  for Python 3.10; `LiteralString` from `typing_extensions` on < 3.11.
- **Naming:** Classes PascalCase, methods/attrs snake_case, enums
  UPPER_CASE values, private attrs `_prefixed`.
- **Docstrings:** reStructuredText style (`:param name:`, `:returns:`).
- **Design principles:**
  1. Side-effect-free constructors — no network I/O in `__init__`
  2. Auth as strategy objects — not factory functions
  3. Keyword-only args — after the first 1-2 positional params
  4. No mutable defaults — use `None` everywhere
  5. Explicit `json`/`data` split — no magic body inference
  6. Clean `__all__` — typed, intentional public surface
  7. Secret protection — `HiddenString` on all credential fields

## Deprecations (v8.0)

- **Plural enum aliases:** `Services` → `Service`, `HttpMethods` → `HttpMethod`,
  `A2ATypes` → `A2AType`, `SshKeyFormats` → `SshKeyFormat`.
- **`HiddenString.get_value()`** → Use `.value` property instead.

## Versioning and release

Version is in `pyproject.toml` but **do not edit manually** — CI stamps from
Git tag via `versionnumber.ps1`. Releases publish to PyPI automatically when a
tag is pushed (`twine` via `pypiOneIdentity` service connection).

## On-demand skills

The following skills provide deeper reference material. Read the `SKILL.md`
when your current task matches the trigger.

| Skill | When to read | File |
|-------|-------------|------|
| Testing Guide | Running/writing tests, test failures, live appliance setup | `.agents/skills/testing-guide/SKILL.md` |
| API Patterns | HTTP methods, streaming, errors, A2A, token lifecycle | `.agents/skills/api-patterns/SKILL.md` |
| Architecture | Module internals, auth flow, events, PKCE, HiddenString | `.agents/skills/architecture/SKILL.md` |
