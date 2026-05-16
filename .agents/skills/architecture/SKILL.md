---
name: architecture
description: >-
  Use when working on PySafeguard module internals, adding new auth
  strategies, extending the client, working with the event system
  (SignalR), or understanding internal patterns like PKCE, HiddenString,
  or async lazy imports.
---

# Architecture

## Authentication Flow

The full login flow, step by step:

1. **Construct client** — `SafeguardClient("host", auth=PasswordAuth(...))`.
   No network I/O happens here (side-effect-free constructor).
2. **Call `login()`** (or enter a context manager, which calls it automatically).
3. **Auth strategy authenticates** — `auth.authenticate(client)` is called:
   - Resolves the identity provider name to an ID via
     `GET /RSTS/AuthenticationProviders`
   - POSTs to `RSTS/oauth2/token` with grant-specific body
     (password grant, client credentials, or PKCE code exchange)
   - Returns an rSTS access token string
4. **rSTS → Safeguard token exchange** — the client POSTs the rSTS token to
   `Service.CORE/Token/LoginResponse` and receives a Safeguard `UserToken`.
5. **Token stored** — `UserToken` is set as `Authorization: Bearer <token>`
   on subsequent requests.
6. **Logout** — `client.logout()` POSTs to `Token/Logout`, then clears the
   local token.

## Auth Protocol

Defined in `auth.py` as a `@runtime_checkable` `Protocol`:

```python
class Auth(Protocol):
    @property
    def can_refresh(self) -> bool: ...

    def authenticate(self, client: SafeguardClient) -> str: ...
    def refresh(self, client: SafeguardClient) -> str: ...
    async def async_authenticate(self, client: AsyncSafeguardClient) -> str: ...
    async def async_refresh(self, client: AsyncSafeguardClient) -> str: ...
```

All methods return an rSTS access token string. The client then exchanges
it for a `UserToken` internally.

## Auth Strategy Implementations

### PasswordAuth

```python
PasswordAuth(provider: str, username: str, password: str | HiddenString)
```

- Uses Resource Owner Grant (`grant_type=password`)
- `can_refresh = True`
- Password auto-wrapped in `HiddenString`
- `dispose()` zeroes the password

### CertificateAuth

```python
CertificateAuth(cert_file: str, key_file: str, provider: str = "certificate")
```

- Uses client credentials grant (`grant_type=client_credentials`)
- `can_refresh = True`
- Sends cert via `cert=(cert_file, key_file)` tuple on requests
- No secrets to dispose (cert files are paths)

### PkceAuth

```python
PkceAuth(
    provider: str,
    username: str,
    password: str | HiddenString,
    secondary_password: str | HiddenString | None = None,
)
```

- Non-interactive browser-less PKCE flow (recommended for newer appliances)
- `can_refresh = True` only when `secondary_password is None` (no MFA)
- Both password and secondary_password auto-wrapped in `HiddenString`
- `dispose()` zeroes both secrets

### TokenAuth

```python
TokenAuth(token: str | HiddenString)
```

- Pre-existing bearer token, no refresh capability
- `can_refresh = False`
- `refresh()` always raises `SafeguardError`
- Token auto-wrapped in `HiddenString`

## Adding a New Auth Strategy

1. **Implement the `Auth` protocol** in `auth.py`:
   - Define `can_refresh` property
   - Implement `authenticate()` and `refresh()` (sync)
   - Implement `async_authenticate()` and `async_refresh()`
   - Wrap any secrets in `HiddenString`
   - Add a `dispose()` method to zero sensitive fields

2. **Export from `__init__.py`**:
   - Import the class in the top-level imports
   - Add to the `__all__` list

3. **Add tests**:
   - Unit test in `tests/test_auth.py` (protocol conformance + construction)
   - Integration test in `tests/integration/` if the strategy involves live
     appliance I/O

4. **Update AGENTS.md**:
   - Add to the auth strategies table in the always-on section

## PKCE Non-Interactive Flow

`pkce.py` implements the full rSTS PKCE authentication flow without a
browser. This is the **recommended** method on newer appliances where Resource
Owner Grant (ROG) is disabled by default.

### Flow Steps

1. Generate CSRF token, PKCE code verifier, and code challenge
2. Set `CsrfToken` cookie manually on the session
3. Resolve identity provider via `GET /RSTS/AuthenticationProviders`
4. POST `loginRequestStep=1` — initialize login
5. POST `loginRequestStep=3` — submit primary credentials (username/password)
6. If MFA required:
   - POST `loginRequestStep=7` — initialize secondary auth
   - POST `loginRequestStep=5` — submit secondary credentials
7. POST `loginRequestStep=6` — generate claims, extract authorization code
   from the `RelyingPartyUrl` query string
8. Exchange authorization code for rSTS access token via
   `POST /RSTS/oauth2/token` with `grant_type=authorization_code`
9. Exchange rSTS token for Safeguard `UserToken` via
   `POST /service/core/v4/Token/LoginResponse`

### Key Implementation Details

- Uses `redirect_uri=urn:InstalledApplication` (no actual redirect)
- All requests are direct HTTP form posts to `/RSTS/UserLogin/LoginController`
- Provider resolution: exact ID match → exact name match → substring match
- `async_pkce.py` mirrors the sync flow using `aiohttp`

## Event System

### Components

| Class | Purpose |
|-------|---------|
| `SafeguardEventListener` | One-shot SignalR listener with bearer token auth |
| `PersistentSafeguardEventListener` | Auto-reconnecting listener that re-authenticates on disconnect |
| `EventHandlerRegistry` | Thread-safe container for event name → handler mappings |
| `EventListenerState` | Enum: `STARTING`, `CONNECTED`, `DISCONNECTED`, `RECONNECTING`, `STOPPED` |

### EventHandlerRegistry

- Thread-safe with a `threading.Lock`
- Event names are case-folded for matching
- `register(event_name, handler)` — appends handler
- `handle_event(raw_event)` — parses JSON, dispatches by `Name` field
- **A2A workaround:** If `Name` is numeric, the real event name is extracted
  from `Data.EventName`
- Handler exceptions are logged and swallowed (never crash the listener)

### SafeguardEventListener Lifecycle

```python
listener = SafeguardEventListener("host", access_token, verify=False)
listener.on("AssetCreated", my_handler)
listener.on_state_change(my_state_callback)
listener.start()
# ... events flow ...
listener.stop()
```

- `start()` builds a SignalR hub connection to `Service.EVENT/signalr`
- Configures bearer token factory, TLS options, and `JsonHubProtocol(version=1)`
- Registers for all events in the `EventHandlerRegistry`
- `stop()` stops the hub and emits `STOPPED` state
- Supports context manager (`with listener:`)

### PersistentSafeguardEventListener

Auto-reconnecting wrapper that re-authenticates when the connection drops.

```python
listener = PersistentSafeguardEventListener.from_password(
    "host", "local", "admin", "secret", verify=False,
)
listener.on("UserCreated", handler)
listener.start()
```

- **Factory methods:** `from_password(...)` and `from_certificate(...)` create
  token factories that construct a fresh `SafeguardClient`, log in, and return
  the token
- On `DISCONNECTED`: schedules reconnect on a daemon thread
- `_reconnect_loop()` sleeps `retry_seconds` (default 5.0), re-auths, reconnects
- Previous client is logged out best-effort on each reconnection
- `stop()` stops inner listener, joins reconnect thread, emits `STOPPED`

### Client Factory Methods

`SafeguardClient` provides convenience methods to create event listeners
from an authenticated client:

```python
listener = client.get_event_listener()              # SafeguardEventListener
persistent = client.get_persistent_event_listener()  # PersistentSafeguardEventListener
```

**Note:** `AsyncSafeguardClient` does **not** have event listener factory
methods. Create listeners directly using the sync client or construct them
manually.

### signalrcore Protocol Version Bug

signalrcore 1.0.2 incorrectly uses `negotiateVersion` (the negotiate
*endpoint* protocol version) as the hub protocol version. Safeguard returns
`negotiateVersion: 0`, causing handshake failure. The workaround in
`_json_hub_protocol()` explicitly constructs `JsonHubProtocol(version=1)`.

## HiddenString

Wraps sensitive values to prevent casual exposure in logs, repr, and debugger
output.

### Storage

Uses mutable `bytearray` internally (not `str`) to enable explicit zeroing
on disposal.

### API

| Method/Property | Behavior |
|----------------|----------|
| `.value` | Returns decoded UTF-8 string; raises `ValueError` if disposed |
| `.get_value()` | **Deprecated** — alias for `.value` |
| `dispose()` | Zeroes each byte, sets internal buffer to `None` |
| `__repr__` | Always `"HiddenString(***)"` |
| `__str__` | Always `"***"` |
| `__bool__` | `False` if disposed or empty |
| `__len__` | Character count, or 0 if disposed |
| `__eq__` | Compares underlying bytes; two disposed instances are equal |
| `__hash__` | Raises `TypeError` (unhashable) |

### Context Manager

```python
with HiddenString("secret") as s:
    print(s.value)  # "secret"
# s is disposed here — s.value raises ValueError
```

### Copy/Pickle Blocking

`__reduce_ex__`, `__getstate__`, `__copy__`, and `__deepcopy__` all raise
`TypeError("HiddenString cannot be pickled")` to prevent accidental
serialization of secrets.

## Async Lazy Imports

`AsyncSafeguardClient` and `AsyncA2AContext` are lazily imported via
`__getattr__` in `__init__.py`:

```python
_ASYNC_LAZY_IMPORTS: dict[str, str] = {
    "AsyncSafeguardClient": ".async_client",
    "AsyncA2AContext": ".async_a2a",
}
```

On first access:
- If `aiohttp` is installed → import succeeds transparently
- If `aiohttp` is missing → raises:
  ```
  ImportError: AsyncSafeguardClient requires the 'async' extra.
  Install it with: pip install pysafeguard[async]
  ```

This means `import pysafeguard` always works, even without aiohttp installed.
The async classes only fail when actually accessed.

## Sync/Async Parity

`AsyncSafeguardClient` mirrors `SafeguardClient` method-for-method:

- Same constructor signature
- Same HTTP methods (`get`, `post`, `put`, `delete`, `request`, `stream`,
  `download`, `upload`)
- Same token lifecycle (`login`, `logout`, `refresh_access_token`,
  `token_lifetime_remaining`)

**Convention:** New I/O features added to `SafeguardClient` should always
have async counterparts in `AsyncSafeguardClient`. Same applies to
`A2AContext` / `AsyncA2AContext`.

## Updating the Public API Surface

All public exports are defined in `__init__.py`'s `__all__` list. When adding
a new public class or type:

1. Import it in the top-level imports section of `__init__.py`
2. Add it to `__all__` in the appropriate category (clients, auth, errors,
   enums, A2A, events, types)
3. If it's an async class that depends on `aiohttp`, add it to
   `_ASYNC_LAZY_IMPORTS` instead of importing directly

## Design Principles in Practice

1. **Side-effect-free constructors** — `__init__` stores parameters only.
   No HTTP calls, no file I/O, no validation that contacts external services.

2. **Auth as strategy objects** — Auth logic lives in `Auth` implementations,
   not in the client. The client calls `auth.authenticate(self)` and doesn't
   know the grant type.

3. **Keyword-only args** — After the first 1-2 positional params (`service`,
   `endpoint`), everything is keyword-only (`*`).

4. **No mutable defaults** — Always `None` as default, never `{}` or `[]`.

5. **Explicit `json`/`data` split** — No magic body inference. Caller chooses.

6. **Clean `__all__`** — Every public symbol is intentionally exported and
   typed. No star imports.

7. **Secret protection** — All credential fields use `HiddenString` with
   `repr=False` equivalent behavior. Secrets never appear in `repr()`,
   `str()`, or casual logging.

## URL Assembly Helpers

`utility.py` provides:

- `assemble_path(*args)` — joins non-None path segments with `/`
- `assemble_url(netloc, path, query, fragment, scheme)` — builds full URL
  via `urlunparse` + `urlencode`
- `get_access_token(data)` — extracts `access_token` from rSTS response dict
- `get_user_token(data)` — extracts `UserToken` from login response dict

## Python Compatibility

- **StrEnum shim** (`data_types.py`): Provides `StrEnum` for Python 3.10
  (before `enum.StrEnum` was added in 3.11).
- **LiteralString** (`utility.py`): Conditionally imported from
  `typing_extensions` on Python < 3.11.
