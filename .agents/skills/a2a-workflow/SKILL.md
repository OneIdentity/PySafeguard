---
name: a2a-workflow
description: Use when setting up or troubleshooting Safeguard A2A certificate registrations, API keys, credential retrieval, brokering, or A2A-backed event listeners.
---

# A2A workflow

## 1. What A2A is

PySafeguard's A2A support is centered on `A2AContext` and `AsyncA2AContext`, thin wrappers over Safeguard's Application-to-Application APIs. The normal A2A credential calls (`retrieve_password`, `set_password`, `retrieve_private_key`, `set_private_key`, `retrieve_api_key_secret`) do **not** use a user bearer token. Instead, each request combines a trusted client certificate on the TLS connection with an `Authorization: A2A <api_key>` header that identifies the specific retrievable account registration. The one exception is `get_retrievable_accounts()`, which lazily logs in with `CertificateAuth` and queries Core API registration data.

### Relevant SDK surface

| Item | Location | Notes |
|---|---|---|
| `A2AContext` | `src/pysafeguard/a2a.py` | Sync A2A helper built on `SafeguardClient` |
| `AsyncA2AContext` | `src/pysafeguard/async_a2a.py` | Async mirror built on `AsyncSafeguardClient` |
| `A2AType` | `src/pysafeguard/data_types.py` | `PASSWORD`, `PRIVATEKEY`, `APIKEYSECRET` |
| `SshKeyFormat` | `src/pysafeguard/data_types.py` | `OPENSSH`, `SSH2`, `PUTTY` |
| `HiddenString` | `src/pysafeguard/hidden_string.py` | Returned for passwords/private keys |
| `SafeguardEventListener` | `src/pysafeguard/event.py` | Used for A2A-backed SignalR listeners |

### Supported A2A credential types

| Enum value | Meaning | Primary method |
|---|---|---|
| `A2AType.PASSWORD` | Managed password retrieval | `retrieve_password()` / `set_password()` |
| `A2AType.PRIVATEKEY` | SSH private key retrieval | `retrieve_private_key()` / `set_private_key()` |
| `A2AType.APIKEYSECRET` | API key secret retrieval | `retrieve_api_key_secret()` |

## 2. Setup flow

The repository's most concrete A2A setup reference is `tests/integration/test_a2a.py`. That fixture builds a complete appliance-side A2A environment and is the best source of truth for how the SDK expects the feature to be provisioned.

### Appliance-side setup sequence

1. Acquire or generate a PEM client certificate and matching private key
2. Upload the certificate to `Service.CORE`, endpoint `TrustedCertificates`
3. Create a certificate-backed user whose `PrimaryAuthenticationProvider` is certificate auth (`Id: -2`) and whose `Identity` is the cert thumbprint
4. Create or identify the asset account that should be retrievable
5. Create an A2A registration with `POST Service.CORE, "A2ARegistrations"`
6. Set `CertificateUserId` on that registration
7. If write-back is required, enable `BidirectionalEnabled` on the registration before calling `set_password()` or `set_private_key()`
8. Add retrievable accounts with `POST A2ARegistrations/{reg_id}/RetrievableAccounts`
9. Persist the returned `ApiKey` securely; that value becomes the `api_key` argument passed to SDK methods

### What the integration tests actually provision

`tests/integration/test_a2a.py` creates:

- a trusted self-signed client certificate
- a certificate user linked to the uploaded cert thumbprint
- an `Other Managed` asset
- a password-managed account
- a second account with an SSH key
- an A2A registration with both password and private-key retrievable accounts
- `BidirectionalEnabled = True` so mutation APIs can be exercised

That makes the tests a good recipe when you need a disposable appliance setup for real validation.

### Minimal sync usage

```python
from pysafeguard import A2AContext

with A2AContext(host, cert_file, key_file, verify=ca_file) as ctx:
    password = ctx.retrieve_password(api_key)
    print(password.value)
```

### Minimal async usage

```python
from pysafeguard import AsyncA2AContext

async with AsyncA2AContext(host, cert_file, key_file, verify=ca_file) as ctx:
    password = await ctx.retrieve_password(api_key)
    print(password.value)
```

### Constructor rules

Both context classes enforce certificate input up front:

- `cert_file` is required
- `key_file` is required
- missing either raises `ValueError("cert_file and key_file are required for A2A context")`

`verify` accepts the same forms as the main client classes:

- `True` - use system trust
- `False` - disable TLS verification
- `str` - CA bundle path

## 3. Credential retrieval

### Core methods

| Method | Returns | Notes |
|---|---|---|
| `retrieve_password(api_key)` | `HiddenString` | GET `Service.A2A/Credentials?type=password` |
| `set_password(api_key, password)` | `None` | PUT `Credentials/Password` with JSON body |
| `retrieve_private_key(api_key, key_format=...)` | `HiddenString` | Adds `key_format` query param for private-key retrieval |
| `set_private_key(api_key, private_key, passphrase="", key_format=...)` | `None` | PUT `Credentials/SshKey` with `PrivateKey` and `Passphrase` |
| `retrieve_api_key_secret(api_key)` | `JsonType` | Raw JSON result, not `HiddenString` |
| `get_retrievable_accounts(filter=None)` | `list[dict[str, JsonType]]` | Uses Core API, not direct A2A auth |

### One-shot helpers

`A2AContext` includes convenience helpers when you do not want to keep a context open:

- `A2AContext.quick_retrieve_password(...)`
- `A2AContext.quick_retrieve_private_key(...)`
- `AsyncA2AContext.quick_retrieve_password(...)`
- `AsyncA2AContext.quick_retrieve_private_key(...)`

There is **no** quick helper for API key secret retrieval today; create a context and call `retrieve_api_key_secret()` directly.

### HiddenString handling

Passwords and private keys are wrapped in `HiddenString`.

- prefer `.value` to access plaintext
- `.get_value()` still works, but is deprecated in favor of `.value`
- `print(secret)` shows `***`
- `repr(secret)` shows `HiddenString(***)`
- `dispose()` zeroes the internal bytearray buffer
- the object also works as a context manager for scoped secret use

Example:

```python
with A2AContext(host, cert_file, key_file, verify=ca_file) as ctx:
    with ctx.retrieve_password(api_key) as password:
        use_password(password.value)
```

### Retrievable account discovery

`get_retrievable_accounts()` is special:

- it lazily sets `self._conn._auth = CertificateAuth(...)`
- it calls `login()` to obtain a user token
- it lists `A2ARegistrations`
- it queries each registration's `RetrievableAccounts`
- it decorates each account with registration metadata:
  - `ApplicationName`
  - `Description`
  - `Disabled`

Use this when you need inventory/discovery behavior, not when you already have an API key.

## 4. Brokering

A2A brokering is supported in both sync and async contexts.

### API surface

- `A2AContext.broker_access_request(api_key, access_request)`
- `AsyncA2AContext.broker_access_request(api_key, access_request)`

### How it works

The SDK sends:

- `POST Service.A2A, "AccessRequests"`
- JSON body = the `access_request` dict you provide
- headers include `Authorization: A2A <api_key>`
- client cert tuple is passed through the request

On success, the method returns the created access request identifier as `str`.

### Important limitation

The SDK does **not** define a higher-level request model for brokering. You must construct the `access_request` payload yourself to match the Safeguard appliance API you are targeting. There is also no sample script or integration test for brokering in this repository, so validate the payload against a live appliance before depending on it.

## 5. Event listeners / SignalR

A2A contexts can produce SignalR listeners even though the listener implementation itself lives in `event.py`.

### Listener factory methods

| Method | Returns | Notes |
|---|---|---|
| `get_event_listener(api_key)` | `SafeguardEventListener` | Uses the A2A API key as the SignalR access token |
| `get_persistent_event_listener(api_key)` | `PersistentSafeguardEventListener` | Reconnects with `token_factory=lambda: api_key` |

### Async behavior

`AsyncA2AContext.get_event_listener()` and `.get_persistent_event_listener()` are still **synchronous** methods that return the same thread-based listener classes used by the sync API. The integration tests explicitly verify this behavior.

### SignalR prerequisites

- install the `signalr` extra: `pip install pysafeguard[signalr]`
- listener connects to `Service.EVENT/signalr`
- if `verify` is a CA path, `event.py` builds an `ssl.SSLContext` for `signalrcore`
- if `verify` is `False`, the listener disables WebSocket TLS verification

### A2A-specific event handling quirk

`EventHandlerRegistry.handle_event()` has an A2A workaround: if the incoming event `Name` is numeric, it extracts the real event name from `Data.EventName`. Preserve that behavior when changing listener code; it matches the SafeguardDotNet behavior expected by the appliance.

### General listener usage pattern

The sample files `samples/SignalRExample.py` and `samples/PersistentSignalRExample.py` show the standard listener lifecycle:

- call `.on("EventName", handler)` to register handlers
- optionally call `.on_state_change(callback)`
- call `.start()`
- call `.stop()` or leave the context manager

A2A listeners use the same API; the only difference is that you obtain them from `A2AContext` with an API key instead of from an authenticated `SafeguardClient`.

## 6. Error scenarios and troubleshooting

### Common configuration failures

- Missing `cert_file` or `key_file` -> `ValueError`
- Empty `api_key` -> `ValueError("api_key must not be empty")`
- Untrusted or mismatched certificate -> request/login failures from the appliance
- Cert user or registration not configured -> A2A or Core API authorization failures

### Authentication and authorization failures

Integration tests show that an invalid API key raises `AuthorizationError` with status code `403` for both sync and async retrieval methods.

If the error comes from `get_retrievable_accounts()`, remember that the failing path is certificate-backed user login against the Core API, not direct `Authorization: A2A ...` credential retrieval.

### Content-type gotcha for password updates

`set_password()` uses `json=` internally. If you bypass the helper and call the endpoint yourself with `data=`, Safeguard returns `415 Unsupported Media Type`. Use the SDK helper or send JSON manually.

### Extras and import failures

- `AsyncA2AContext` depends on the `async` extra (`aiohttp`)
- SignalR listeners depend on the `signalr` extra (`signalrcore`)
- `event.py` raises a helpful `SafeguardError` when `signalrcore` is missing

### SignalR handshake issue

`signalrcore` 1.0.2 has a protocol-version bug. PySafeguard works around it by forcing `JsonHubProtocol(version=1)`. If A2A event listeners suddenly start failing after listener refactors, verify that `_json_hub_protocol()` still forces version `1`.

### TLS troubleshooting

Use a CA bundle path instead of `verify=False` whenever possible.

Helpful environment variables for appliance environments that use an internal CA:

- `REQUESTS_CA_BUNDLE` for HTTP requests
- `WEBSOCKET_CLIENT_CA_BUNDLE` for SignalR/WebSocket traffic

### Safe debugging rules

- never print or log `password.value` or private-key plaintext in committed samples/tests
- prefer inspecting `HiddenString` redacted behavior unless plaintext is strictly required
- dispose transient secrets promptly when writing new helpers
- do not commit client certs, private keys, A2A API keys, or captured access-request payloads
