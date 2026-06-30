---
name: testing-guide
description: >-
  Use when running tests, writing tests, investigating test failures,
  or setting up a test environment against a live Safeguard appliance.
  Covers pytest configuration, pytest-asyncio, integration test setup,
  environment variables, and the preflight fixture.
---

# Testing Guide

## Running Tests

```bash
# Unit tests (no live appliance required)
poetry run python -m pytest tests/ -m "not integration"

# Integration tests (requires live appliance)
SPP_HOST=<host> SPP_USERNAME=<user> SPP_PASSWORD=<pass> poetry run python -m pytest tests/ -m integration

# Single test file
poetry run python -m pytest tests/test_auth.py -v

# Single test by name
poetry run python -m pytest tests/ -k "test_password_auth_defaults" -v
```

## pytest Configuration

Configured in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
markers = ["integration: requires a live Safeguard appliance"]
testpaths = ["tests"]
```

**Key detail:** `asyncio_mode = "auto"` means async test functions run
automatically — you do **not** need `@pytest.mark.asyncio` on every async test.

## Unit Test Patterns

Unit tests live in `tests/` (top level, not `tests/integration/`). They use
mocked HTTP and never contact a live appliance.

### Conventions

- **Class-based grouping:** Group related tests in classes
  (`TestPasswordAuth`, `TestSafeguardClientInit`).
- **No live I/O:** Use `unittest.mock.patch`, `MagicMock`, and
  `unittest.mock.AsyncMock` for HTTP calls.
- **Explicit cleanup:** Call `.close()` on constructed clients in tests that
  don't use a context manager.
- **Module docstrings:** Each test file starts with a docstring explaining
  what it covers and that no live appliance is needed.

### Example structure

```python
"""Tests for PasswordAuth construction and protocol conformance.

No live appliance required — all HTTP is mocked.
"""
from unittest.mock import MagicMock, patch

import pytest

from pysafeguard import PasswordAuth, SafeguardClient


class TestPasswordAuth:
    def test_defaults(self) -> None:
        auth = PasswordAuth("local", "admin", "secret")
        assert auth.can_refresh is True

    def test_hidden_string_wrapping(self) -> None:
        auth = PasswordAuth("local", "admin", "secret")
        assert repr(auth._password) == "HiddenString(***)"
```

### Async unit tests

```python
async def test_async_client_login(self) -> None:
    """asyncio_mode=auto handles this — no decorator needed."""
    with patch("pysafeguard.async_client.aiohttp.ClientSession"):
        client = AsyncSafeguardClient("host", auth=mock_auth)
        # ...
```

## Integration Tests

Integration tests live in `tests/integration/` and interact with a real
Safeguard appliance. They are **automatically skipped** when `SPP_HOST` is
not set.

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SPP_HOST` | **Yes** | — | Appliance hostname or IP. Tests auto-skip when unset. |
| `SPP_USERNAME` | No | `Admin` | Safeguard user for authentication. |
| `SPP_PASSWORD` | **Yes** | — | Password for the Safeguard user. |
| `SPP_CA_FILE` | No | — | Path to CA certificate file. Omit to disable TLS verification. |
| `SPP_DEVICE_CODE_INTERACTIVE` | No | — | Set to `1` to run the human-approval Device Code login test. Requires `SPP_HOST`; the test stays skipped otherwise. |

### Auto-skip Mechanism

In `tests/conftest.py`, `pytest_collection_modifyitems()` adds a skip marker
to any test with the `integration` keyword when `SPP_HOST` is unset. This
means integration tests are silently skipped in CI or local runs without an
appliance.

### Preflight Fixture: Resource Owner Grant

`tests/integration/conftest.py` defines an `autouse=True`, session-scoped
fixture `_ensure_resource_owner_grant` that:

1. Tries `PasswordAuth` login — if it works, ROG is already enabled.
2. If password login fails, uses `PkceAuth` to log in instead.
3. Reads `Service.CORE/Settings` and enables the `"ResourceOwner"` grant type
   if missing.
4. **Restores the original setting** after the test session completes.

This mirrors the behavior in SafeguardDotNet and safeguard-ps test runners.

### Shared Fixtures

Defined in `tests/integration/conftest.py`:

| Fixture | Scope | Description |
|---------|-------|-------------|
| `spp_host` | session | `SPP_HOST` env var |
| `spp_username` | session | `SPP_USERNAME` (default `"Admin"`) |
| `spp_password` | session | `SPP_PASSWORD` env var |
| `spp_verify` | session | `SPP_CA_FILE` path or `False` |
| `sync_connection` | function | Logged-in `SafeguardClient` with `PasswordAuth` |
| `async_connection` | function | Logged-in `AsyncSafeguardClient` with `PasswordAuth` |
| `unique_name` | function | `PySg_<8hex>` prefix for test resource names |

### Cleanup Helpers

`delete_user_sync()` and `delete_user_async()` in `tests/integration/conftest.py`
silently ignore 404/not-found errors during cleanup. Use these instead of raw
DELETE calls in teardown.

### Writing a New Integration Test

1. Create the file in `tests/integration/` (e.g., `test_my_feature.py`).
2. Add the module-level marker:
   ```python
   pytestmark = pytest.mark.integration
   ```
3. Use the shared fixtures (`sync_connection`, `async_connection`, etc.).
4. Follow the naming convention: `test_<feature>_sync.py` / `test_<feature>_async.py`.

## Known Gotchas

### signalrcore Protocol Version Bug

`signalrcore` 1.0.2 has a bug: it uses the negotiate endpoint's
`negotiateVersion` (which Safeguard returns as `0`) as the SignalR hub protocol
version. This causes a handshake failure:

> "The server does not support version 0 of the 'json' protocol."

**Workaround** (already applied in `src/pysafeguard/event.py`):

```python
from signalrcore.protocol.json_hub_protocol import JsonHubProtocol
protocol = JsonHubProtocol(version=1)
# Pass via hub_connection_builder.with_hub_protocol(protocol)
```

If writing event listener tests, be aware this workaround is applied
automatically by `_json_hub_protocol()`.

### A2A Integration Test Setup

A2A tests (`tests/integration/test_a2a.py`) require extensive appliance setup:

1. **Local test admin** with appropriate roles
2. **Trusted self-signed certificate** uploaded to the appliance
3. **Certificate user** linked to the trusted cert
4. **"Other Managed" asset** with an account
5. **A2A registration** with an API key
6. For `set_password` tests: `BidirectionalEnabled=true` on the registration

The test's session-scoped `a2a_env` fixture handles all of this automatically
(including `openssl` cert generation in a temp directory). Cleanup deletes the
trusted cert by thumbprint.

### TLS Trust for Integration Tests

If the appliance uses a certificate signed by an internal CA, set these
environment variables in addition to the standard test variables:

| Variable | Affects | Description |
|----------|---------|-------------|
| `REQUESTS_CA_BUNDLE` | All HTTP requests | CA bundle path for `requests` |
| `WEBSOCKET_CLIENT_CA_BUNDLE` | SignalR event listeners | CA bundle path for WebSocket |

Alternatively, pass the CA path via `SPP_CA_FILE` — the test fixtures pass it
as `verify=<path>` to client constructors.

### A2A `set_password` Content-Type

A2A `set_password` requires `Content-Type: application/json`. Use `json=`
parameter, not `data=`. Using `data=` results in a **415 Unsupported Media
Type** error.
