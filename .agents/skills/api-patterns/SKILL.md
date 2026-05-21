---
name: api-patterns
description: >-
  Use when making Safeguard API calls via SafeguardClient, working with
  HTTP methods, streaming, error handling, A2A credential retrieval,
  or managing token lifecycle. Covers method signatures, parameter
  conventions, and common patterns.
---

# API Patterns

## HTTP Methods

All methods require an authenticated client (call `login()` or use a context
manager first). The first two positional arguments are always `service` and
`endpoint`.

### GET

```python
client.get(
    service: Service,
    endpoint: str | None = None,
    *,
    params: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    host: str | None = None,
    cert: tuple[str, str] | None = None,
    api_version: str | None = None,
) -> requests.Response
```

### POST

```python
client.post(
    service: Service,
    endpoint: str | None = None,
    *,
    json: JsonType | None = None,
    data: str | None = None,
    params: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    host: str | None = None,
    cert: tuple[str, str] | None = None,
    api_version: str | None = None,
) -> requests.Response
```

### PUT

```python
client.put(
    service: Service,
    endpoint: str | None = None,
    *,
    json: JsonType | None = None,
    data: str | None = None,
    params: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    host: str | None = None,
    cert: tuple[str, str] | None = None,
    api_version: str | None = None,
) -> requests.Response
```

### DELETE

```python
client.delete(
    service: Service,
    endpoint: str | None = None,
    *,
    params: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    host: str | None = None,
    cert: tuple[str, str] | None = None,
    api_version: str | None = None,
) -> requests.Response
```

### request (low-level)

```python
client.request(
    method: HttpMethod,
    service: Service,
    endpoint: str | None = None,
    *,
    params: Mapping[str, str] | None = None,
    json: JsonType | None = None,
    data: str | None = None,
    headers: Mapping[str, str] | None = None,
    host: str | None = None,
    cert: tuple[str, str] | None = None,
    api_version: str | None = None,
) -> requests.Response
```

## Parameter Reference

| Parameter | Type | Description |
|-----------|------|-------------|
| `service` | `Service` | Target API service (CORE, APPLIANCE, etc.) |
| `endpoint` | `str \| None` | URL path after the service prefix (e.g., `"Users"`, `"Assets/123"`) |
| `json` | `JsonType \| None` | Dict/list body — auto-sets `Content-Type: application/json` |
| `data` | `str \| None` | Raw string body — no automatic content-type |
| `params` | `Mapping[str, str] \| None` | Query parameters appended to URL |
| `headers` | `Mapping[str, str] \| None` | Additional headers merged with defaults |
| `host` | `str \| None` | Override target host (useful for clusters) |
| `cert` | `tuple[str, str] \| None` | Client certificate as `(cert_file, key_file)` |
| `api_version` | `str \| None` | Override API version for this request (default: `"v4"`) |

### `json` vs `data` — Important Distinction

- **`json=`** serializes a Python dict/list to JSON and sets
  `Content-Type: application/json`. Use for structured API payloads.
- **`data=`** sends a raw string body with no automatic content-type.
  Use for pre-serialized or non-JSON payloads.
- **Never pass both** — `json=` takes precedence if both are provided.

## Streaming

### stream — Raw streaming response

```python
client.stream(
    method: HttpMethod, service: Service, endpoint: str | None = None,
    *, params=..., json=..., data=..., headers=..., host=..., cert=..., api_version=...,
) -> requests.Response
```

Returns an **unconsumed** response with `stream=True`. Caller is responsible
for iterating `response.iter_content()` or `response.iter_lines()`.

### download — Stream to file

```python
client.download(
    service: Service, endpoint: str, file_path: str | Path,
    *, params=..., headers=..., host=..., cert=..., api_version=...,
    chunk_size: int = 8192,
) -> int  # bytes written
```

### upload — Upload file or bytes

```python
client.upload(
    service: Service, endpoint: str, file_or_stream: str | Path | IO[bytes],
    *, content_type: str = "application/octet-stream",
    params=..., headers=..., host=..., cert=..., api_version=...,
) -> requests.Response
```

Accepts a file path (string/Path) or an open binary stream.

## Safeguard API Services

| Enum | URL path | Description |
|---|---|---|
| `Service.CORE` | `service/core` | Primary API: assets, users, policies, access requests |
| `Service.APPLIANCE` | `service/appliance` | Appliance management: networking, diagnostics, backups |
| `Service.NOTIFICATION` | `service/notification` | Anonymous status and notification endpoints |
| `Service.A2A` | `service/a2a` | Application-to-Application credential retrieval |
| `Service.EVENT` | `service/event` | SignalR event streaming |
| `Service.RSTS` | `RSTS` | Embedded secure token service (authentication) |

The default API version is **v4** (since Safeguard 7.0).

## Error Handling

### Error Hierarchy

```
SafeguardError (base)
├── ApiError (HTTP error responses)
│   ├── AuthenticationError (401)
│   ├── AuthorizationError (403)
│   └── NotFoundError (404)
└── TransportError (network/connection failures)
```

### Error Attributes

All `SafeguardError` subclasses carry:

| Attribute | Type | Description |
|-----------|------|-------------|
| `status_code` | `int \| None` | HTTP status code |
| `error_code` | `int \| None` | Safeguard-specific error code (from response `Code` field) |
| `error_message` | `str \| None` | Safeguard error message (from response `Message` field) |
| `response_body` | `str \| None` | Raw response body text |

### Automatic Status Code Mapping

`ApiError.from_response(resp)` auto-maps HTTP status codes:

- `401` → `AuthenticationError`
- `403` → `AuthorizationError`
- `404` → `NotFoundError`
- All others → `ApiError`

The error message is formatted as: `"{status_code} {reason}: {method} {url}\n{body}"`

### Catching Errors

```python
from pysafeguard import SafeguardClient, Service, NotFoundError, ApiError

with SafeguardClient(...) as client:
    try:
        user = client.get(Service.CORE, "Users/99999").json()
    except NotFoundError:
        print("User not found")
    except ApiError as e:
        print(f"API error {e.status_code}: {e.error_message}")
```

## Token Lifecycle

### Manual refresh

```python
client.refresh_access_token()
```

Requires the auth strategy to support refresh (`can_refresh=True`).
`PasswordAuth` and `CertificateAuth` support refresh. `TokenAuth` does not.
`PkceAuth` supports refresh only when no secondary password (MFA) is configured.

### Check remaining lifetime

```python
remaining = client.token_lifetime_remaining  # int | None (seconds)
```

Queries `Service.APPLIANCE/SystemTime` and reads the
`x-tokenlifetimeremaining` response header.

### Auto-refresh

```python
client = SafeguardClient("host", auth=auth, auto_refresh=True)
```

When enabled, every `request()`, `stream()`, and `upload()` call checks
the token lifetime before executing. If the token is expired or missing,
it automatically calls `refresh_access_token()`.

Auto-refresh is skipped for `Service.RSTS` and `Service.APPLIANCE` requests
to avoid circular refresh loops.

### Logout

```python
client.logout()
```

POSTs to `Service.CORE/Token/Logout` to invalidate the token on the
appliance, then clears the local token. Errors during logout are silently
ignored (best-effort).

## A2A (Application-to-Application)

### Context Manager Pattern

```python
from pysafeguard import A2AContext

with A2AContext("host", "cert.pem", "key.pem", verify=False) as ctx:
    password = ctx.retrieve_password("my-api-key")
    ctx.set_password("my-api-key", "new-password")
    private_key = ctx.retrieve_private_key("my-api-key")
    secret = ctx.retrieve_api_key_secret("my-api-key")
```

### Quick One-Shot Retrieval

```python
password = A2AContext.quick_retrieve_password(
    "host", "api-key", "cert.pem", "key.pem", verify=False,
)
private_key = A2AContext.quick_retrieve_private_key(
    "host", "api-key", "cert.pem", "key.pem",
    key_format=SshKeyFormat.OPENSSH, verify=False,
)
```

### A2A Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `retrieve_password(api_key)` | `HiddenString` | Retrieve managed password |
| `set_password(api_key, password)` | `None` | Update managed password |
| `retrieve_private_key(api_key, *, key_format=OPENSSH)` | `HiddenString` | Retrieve SSH private key |
| `set_private_key(api_key, key, passphrase, *, key_format=OPENSSH)` | `None` | Update SSH private key |
| `retrieve_api_key_secret(api_key)` | `JsonType` | Retrieve API key secret |
| `broker_access_request(api_key, access_request)` | `str` | Submit an access request |
| `get_retrievable_accounts(*, filter=None)` | `list[dict]` | List accounts (uses cert auth) |

### HiddenString return values

Methods that return secrets (like `A2AContext.retrieve_password()`) return a
`HiddenString` object that displays as `***` when printed, formatted, or
converted with `str()`. To access the raw value:

```python
password = ctx.retrieve_password(api_key)
print(password)          # prints: ***
print(password.value)    # prints the actual password string
raw = password.value
```

This prevents accidental credential leakage in logs or REPL output.

### A2A Authorization Header

A2A requests use `Authorization: A2A <apiKey>` (not Bearer).

### A2A Gotcha: `set_password` Content-Type

`set_password` sends the password via `json=` internally. If you're calling
the raw API yourself, you **must** use `Content-Type: application/json`.
Using `data=` (raw string) results in **415 Unsupported Media Type**.

## TLS / Certificate Verification

The `verify` parameter on `SafeguardClient` and `A2AContext` accepts:

- `True` (default) — use system trust store
- `False` — disable TLS verification (development only)
- `str` — path to a CA bundle file for custom trust

```python
# CA bundle (recommended for production)
client = SafeguardClient("host", auth=auth, verify="/path/to/ca-bundle.pem")

# Disable verification (development only)
client = SafeguardClient("host", auth=auth, verify=False)
```

### Environment Variables for Trust

| Variable | Affects | Description |
|----------|---------|-------------|
| `REQUESTS_CA_BUNDLE` | All HTTP requests | CA bundle path for `requests` library |
| `WEBSOCKET_CLIENT_CA_BUNDLE` | SignalR event listeners | CA bundle path for WebSocket connections |

Set these when the appliance uses a certificate signed by an internal CA.

## Common Patterns

### Query parameters

Use the `params` keyword argument (not `parameters`) to pass query string values:

```python
users = client.get(Service.CORE, "Users", params={"fields": "Id,Name", "filter": "Disabled eq false"})
assets = client.get(Service.CORE, "Assets", params={"filter": "Name eq 'MyAsset'"})
```

> **Note:** The keyword is `params` (matching the `requests` library convention),
> not `parameters` (which is the .NET SDK's name for the same concept).

### POST with JSON body

```python
response = client.post(
    Service.CORE, "Users",
    json={"Name": "NewUser", "PrimaryAuthenticationProvider": {"Id": provider_id}},
)
new_user = response.json()
```

### Override API version for a single request

```python
response = client.get(Service.CORE, "Users", api_version="v3")
```

### Override target host (cluster scenario)

```python
response = client.get(Service.CORE, "Users", host="other-node.example.com")
```

## Async Client

`AsyncSafeguardClient` mirrors the sync client exactly. All methods are
`async def` with the same signatures. Use `await` on every call:

```python
async with AsyncSafeguardClient("host", auth=auth, verify=False) as client:
    users = (await client.get(Service.CORE, "Users")).json()
    await client.post(Service.CORE, "Users", json={"Name": "NewUser"})
```

`AsyncA2AContext` similarly mirrors `A2AContext` with async methods.
