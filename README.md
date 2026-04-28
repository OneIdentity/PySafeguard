# PySafeguard
One Identity Safeguard Python SDK

-----------

> **⚠️ Breaking Change: v8.0**
>
> PySafeguard v8.0 is a complete Pythonic redesign of the SDK. The public API has
> changed significantly. If you are upgrading from v7.x, see the
> [Migration Guide](#migrating-from-7x-to-80) at the bottom of this document.

-----------

<p align="center">
<i>Check out our <a href="https://github.com/OneIdentity/PySafeguard/tree/main/samples">sample projects</a> to get started with your own custom integration to Safeguard!</i>
</p>

-----------

## Support

One Identity open source projects are supported through [One Identity GitHub issues](https://github.com/OneIdentity/PySafeguard/issues) and the [One Identity Community](https://www.oneidentity.com/community/). This includes all scripts, plugins, SDKs, modules, code snippets or other solutions. For assistance with any One Identity GitHub project, please raise a new Issue on the [One Identity GitHub project](https://github.com/OneIdentity/PySafeguard/issues) page. You may also visit the [One Identity Community](https://www.oneidentity.com/community/) to ask questions.  Requests for assistance made through official One Identity Support will be referred back to GitHub and the One Identity Community forums where those requests can benefit all users.

## Introduction

All functionality in Safeguard is available via the Safeguard API. There is
nothing that can be done in the Safeguard UI that cannot also be performed
using the Safeguard API programmatically.

PySafeguard is provided to facilitate calling the Safeguard API from Python.
It removes the complexity of dealing with authentication via Safeguard's
embedded secure token service (STS). Create a `SafeguardClient` with an
authentication strategy, and use standard HTTP verb methods (`get`, `post`,
`put`, `delete`) to interact with the API.

PySafeguard also provides an easy way to call Safeguard A2A from Python. The A2A service requires client certificate authentication for retrieving passwords for application integration. When Safeguard A2A is properly configured, specified passwords can be retrieved with a single method call without requiring access request workflow approvals. Safeguard A2A is protected by API keys and IP restrictions in addition to client certificate authentication.

PySafeguard includes an SDK for listening to Safeguard's powerful, real-time event notification system. Safeguard provides role-based event notifications via SignalR to subscribed clients. If a Safeguard user is an Asset Administrator events related to the creation, modification, or deletion of Assets and Asset Accounts will be sent to that user. When used with a certificate user, this provides an opportunity for reacting programmatically to any data modification in Safeguard. Events are also supported for access request workflow and for A2A password changes.

## Installation

This Python module is published to the [PyPi registry](https://pypi.org/project/pysafeguard) to make it as easy as possible to install.

```Bash
> pip install pysafeguard
```

For async support:
```Bash
> pip install pysafeguard[async]
```

For SignalR event listener support:
```Bash
> pip install pysafeguard[signalr]
```

For all extras:
```Bash
> pip install pysafeguard[async,signalr]
```

### Communicating securely with Safeguard using the SDK

When using the SDK to communicate with Safeguard, all communication will
be done using HTTPS.  To keep the communication secure, all certificates
used to secure Safeguard's API should be configured on the system where
the SDK is used.  How this is accomplished varies on each system,
however, here are some tips that can help get started.

If the system is already properly configured, the SDK should work
without any errors.  If there are errors, consider using one of the
following methods to establish trust.

- Environment variable providing path to certificates

  In Bourne Shell:
  ```Bash
  $ export WEBSOCKET_CLIENT_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
  $ export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
  ```
  
  In PowerShell:
  ```Powershell
  > $env:WEBSOCKET_CLIENT_CA_BUNDLE="c:\ssl\certs\ca-certificates.crt"
  > $env:REQUESTS_CA_BUNDLE="c:ssl\certs\ca-certificates.crt"
  ```
  
- Use the `verify` option when creating the `SafeguardClient`

  See examples below for utilizing this method.  While `verify` can be
  used to disable security checking this is not recommended.

> **Note**  
> The WEBSOCKET_CLIENT_CA_BUNDLE environment variable is only necessary
> when working with SignalR.

## Getting Started

A simple code example for calling the Safeguard API with username and password authentication through the local Safeguard STS:

```Python
from pysafeguard import SafeguardClient, PasswordAuth, Service

with SafeguardClient("safeguard.sample.corp",
                     auth=PasswordAuth("local", "Admin", "Admin123"),
                     verify="ssl/pathtoca.pem") as client:
    me = client.get(Service.CORE, "Me", params={"fields": "DisplayName"})
    print(f"Connected to Safeguard as {me.json()['DisplayName']}")
```

Password authentication to an external provider:

```Python
from pysafeguard import SafeguardClient, PasswordAuth

with SafeguardClient("safeguard.sample.corp",
                     auth=PasswordAuth("myexternalprovider", "Admin", "Admin123"),
                     verify="ssl/pathtoca.pem") as client:
    # client is now authenticated
    ...
```

PKCE authentication (recommended for newer appliances):

```Python
from pysafeguard import SafeguardClient, PkceAuth

with SafeguardClient("safeguard.sample.corp",
                     auth=PkceAuth("local", "Admin", "Admin123"),
                     verify="ssl/pathtoca.pem") as client:
    users = client.get(Service.CORE, "Users").json()
```

Client certificate authentication using PEM and KEY files:

```Python
from pysafeguard import SafeguardClient, CertificateAuth

with SafeguardClient("safeguard.sample.corp",
                     auth=CertificateAuth("ssl/pathtocertuser.pem", "ssl/pathtocertuser.key"),
                     verify="ssl/pathtoca.pem") as client:
    me = client.get(Service.CORE, "Me").json()
```

Client certificate authentication to an external provider:

```Python
from pysafeguard import SafeguardClient, CertificateAuth

with SafeguardClient("safeguard.sample.corp",
                     auth=CertificateAuth("ssl/cert.pem", "ssl/key.pem", provider="myexternalprovider"),
                     verify="ssl/pathtoca.pem") as client:
    ...
```

Anonymous connection without TLS verification:

```Python
from pysafeguard import SafeguardClient, Service

client = SafeguardClient("safeguard.sample.corp", verify=False)
system_time = client.get(Service.APPLIANCE, "SystemTime")
client.close()
```

Authentication using an existing Safeguard API token:

```Python
from pysafeguard import SafeguardClient, TokenAuth

with SafeguardClient("safeguard.sample.corp",
                     auth=TokenAuth(my_api_token),
                     verify="ssl/pathtoca.pem") as client:
    me = client.get(Service.CORE, "Me").json()
```

### Async Usage

PySafeguard provides full async support via `AsyncSafeguardClient`:

```Python
from pysafeguard import AsyncSafeguardClient, PasswordAuth, Service

async with AsyncSafeguardClient("safeguard.sample.corp",
                                auth=PasswordAuth("local", "Admin", "Admin123"),
                                verify=False) as client:
    resp = await client.get(Service.CORE, "Users")
    users = await resp.json()
```

## Getting Started With A2A

Once you have configured your A2A registration in Safeguard you can retrieve
an A2A password or private key using a certificate and API key.

To retrieve a password via A2A:

```Python
from pysafeguard import A2AContext

with A2AContext("safeguard.sample.corp", "ssl/cert.pem", "ssl/key.pem",
                verify="ssl/pathtoca.pem") as ctx:
    password = ctx.retrieve_password("myapikey")
```

To retrieve a private key in OpenSSH format via A2A:

```Python
from pysafeguard import A2AContext, SshKeyFormat

with A2AContext("safeguard.sample.corp", "ssl/cert.pem", "ssl/key.pem",
                verify="ssl/pathtoca.pem") as ctx:
    private_key = ctx.retrieve_private_key("myapikey", key_format=SshKeyFormat.OPENSSH)
```

## About the Safeguard API

The Safeguard API is a REST-based Web API. Safeguard API endpoints are called
using HTTP operators and JSON (or XML) requests and responses. The Safeguard API
is documented using Swagger. You may use Swagger UI to call the API directly or
to read the documentation about URLs, parameters, and payloads.

To access the Swagger UI use a browser to navigate to:
`https://<address>/service/<service>/swagger`

- `<address>` = Safeguard network address
- `<service>` = Safeguard service to use

The Safeguard API is made up of multiple services: core, appliance, notification,
and a2a.

|Service|Description|
|-|-|
|core|Most product functionality is found here. All cluster-wide operations: access request workflow, asset management, policy management, etc.|
|appliance|Appliance specific operations, such as setting IP address, maintenance, backups, support bundles, appliance management|
|notification|Anonymous, unauthenticated operations. This service is available even when the appliance isn't fully online|
|a2a|Application integration specific operations. Fetching passwords, making access requests on behalf of users, etc.|

Each of these services provides a separate Swagger endpoint.

You may use the `Authorize` button at the top of the screen to get an API token
to call the Safeguard API directly using Swagger.

### Examples

Most functionality is in the core service as mentioned above. The notification service
provides read-only information for status, etc.

#### Anonymous Call for Safeguard Status

```Python
from pysafeguard import SafeguardClient, Service

client = SafeguardClient("safeguard.sample.corp", verify=False)
result = client.get(Service.NOTIFICATION, "Status")
print(json.dumps(result.json(), indent=2, sort_keys=True))
client.close()
```

#### Get remaining access token lifetime

```Python
from pysafeguard import SafeguardClient, PasswordAuth

with SafeguardClient("safeguard.sample.corp",
                     auth=PasswordAuth("local", "username", "password"),
                     verify="ssl/pathtoca.pem") as client:
    minutes_left = client.token_lifetime_remaining
    print(minutes_left)
```

#### Listen for SignalR events

To use the SignalR functionality, install the signalr extra:

```Bash
> pip install pysafeguard[signalr]
```

```Python
from pysafeguard import SafeguardClient, PasswordAuth

with SafeguardClient("safeguard.sample.corp",
                     auth=PasswordAuth("local", "username", "password"),
                     verify="ssl/pathtoca.pem") as client:
    listener = client.get_event_listener()
    listener.on("AssetCreated", lambda name, body: print(f"Asset created: {name}"))

    with listener:
        listener.start()
        input("Press Enter to stop listening...")
```

#### Create a New User and Set the Password

```Python
from pysafeguard import SafeguardClient, PasswordAuth, Service

user = {
    "PrimaryAuthenticationProvider": {"Id": -1},
    "Name": "MyNewUser",
}

with SafeguardClient("safeguard.sample.corp",
                     auth=PasswordAuth("local", "username", "password"),
                     verify="ssl/pathtoca.pem") as client:
    result = client.post(Service.CORE, "Users", json=user).json()
    user_id = result["Id"]
    client.put(Service.CORE, f"Users/{user_id}/Password", data="MyNewUser123")
```

#### Streaming Downloads

```Python
from pysafeguard import SafeguardClient, PasswordAuth, HttpMethod, Service

with SafeguardClient("safeguard.sample.corp",
                     auth=PasswordAuth("local", "Admin", "Admin123"),
                     verify=False) as client:
    # Stream to file
    bytes_written = client.download(Service.APPLIANCE, "Backups/1/Download", "/tmp/backup.sgb")

    # Or stream manually
    resp = client.stream(HttpMethod.GET, Service.APPLIANCE, "Backups/1/Download")
    with resp:
        for chunk in resp.iter_content(chunk_size=8192):
            process(chunk)
```

---

## Migrating from 7.x to 8.0

PySafeguard 8.0 is a complete redesign of the public API. This guide shows
how to convert your 7.x code to the new API.

### Client Construction

```python
# 7.x
from pysafeguard import PySafeguardConnection
conn = PySafeguardConnection("host", "ssl/ca.pem")
conn.connect_password("Admin", "Admin123")

# 8.0
from pysafeguard import SafeguardClient, PasswordAuth
client = SafeguardClient("host", auth=PasswordAuth("local", "Admin", "Admin123"), verify="ssl/ca.pem")
client.login()
# Or use a context manager (auto login/logout):
with SafeguardClient("host", auth=PasswordAuth("local", "Admin", "Admin123"), verify="ssl/ca.pem") as client:
    ...
```

### Authentication

```python
# 7.x — Factory functions
conn = connect_password("host", "Admin", "pass", verify=False)
conn = connect_certificate("host", "cert.pem", "key.pem")
conn = connect_token("host", my_token)

# 8.0 — Auth strategy objects
client = SafeguardClient("host", auth=PasswordAuth("local", "Admin", "pass"), verify=False)
client = SafeguardClient("host", auth=CertificateAuth("cert.pem", "key.pem"))
client = SafeguardClient("host", auth=TokenAuth(my_token))
```

### API Calls

```python
# 7.x
resp = conn.invoke(HttpMethods.GET, Services.CORE, "Users")
resp = conn.invoke(HttpMethods.POST, Services.CORE, "Users", body={"Name": "Test"})
resp = conn.invoke(HttpMethods.GET, Services.CORE, "Users", query={"filter": "Disabled eq false"})
resp = conn.invoke(HttpMethods.GET, Services.CORE, "Me", additionalHeaders={"X-Custom": "val"})

# 8.0
resp = client.get(Service.CORE, "Users")
resp = client.post(Service.CORE, "Users", json={"Name": "Test"})
resp = client.get(Service.CORE, "Users", params={"filter": "Disabled eq false"})
resp = client.get(Service.CORE, "Me", headers={"X-Custom": "val"})

# Low-level escape hatch (replaces invoke)
resp = client.request(HttpMethod.GET, Service.CORE, "Users")
```

### Enums

```python
# 7.x (plural)                    # 8.0 (singular)
Services.CORE                  →  Service.CORE
HttpMethods.GET                →  HttpMethod.GET
A2ATypes.PASSWORD              →  A2AType.PASSWORD
SshKeyFormats.OPENSSH          →  SshKeyFormat.OPENSSH
```

### Exceptions

```python
# 7.x
from pysafeguard import SafeguardException, WebRequestError
try:
    conn.invoke(...)
except WebRequestError as e:
    print(e.message)

# 8.0
from pysafeguard import SafeguardError, ApiError, AuthenticationError, NotFoundError
try:
    client.get(Service.CORE, "Users")
except NotFoundError:
    print("Not found")
except AuthenticationError:
    print("Auth failed")
except ApiError as e:
    print(f"HTTP {e.status_code}: {e.error_message}")
except SafeguardError as e:
    print(f"Error: {e}")
```

### Streaming

```python
# 7.x
resp = conn.invoke_stream(HttpMethods.GET, Services.APPLIANCE, "Backups/1/Download")
written = conn.download(Services.APPLIANCE, "Backups/1/Download", "/tmp/file.sgb")
resp = conn.upload(Services.APPLIANCE, "Backups/Upload", data, content_type="application/octet-stream")

# 8.0
resp = client.stream(HttpMethod.GET, Service.APPLIANCE, "Backups/1/Download")
written = client.download(Service.APPLIANCE, "Backups/1/Download", "/tmp/file.sgb")
resp = client.upload(Service.APPLIANCE, "Backups/Upload", data, content_type="application/octet-stream")
```

### A2A

```python
# 7.x
password = PySafeguardConnection.a2a_get_credential("host", "apikey", "cert.pem", "key.pem")

# 8.0
from pysafeguard import A2AContext
with A2AContext("host", "cert.pem", "key.pem") as ctx:
    password = ctx.retrieve_password("apikey")
```

### Token Lifetime

```python
# 7.x
minutes = conn.get_remaining_token_lifetime()

# 8.0 (sync)
minutes = client.token_lifetime_remaining  # property

# 8.0 (async)
minutes = await client.get_token_lifetime_remaining()
```

### Properties

```python
# 7.x                             # 8.0
conn.UserToken                 →  client.user_token
conn.apiVersion                →  client.api_version
conn.headers["authorization"]  →  client._headers["authorization"]  # private
```

### Imports

```python
# 7.x
from pysafeguard import *  # PySafeguardConnection, Connection, HttpMethods, Services, ...

# 8.0
from pysafeguard import (
    SafeguardClient,
    AsyncSafeguardClient,
    PasswordAuth,
    CertificateAuth,
    PkceAuth,
    TokenAuth,
    Service,
    HttpMethod,
    SafeguardError,
    ApiError,
    A2AContext,
    HiddenString,
)
```

### Removed

The following have been removed in 8.0 with no direct replacement:

- `PySafeguardConnection` class — use `SafeguardClient`
- `Connection` / `AsyncConnection` (public API) — use `SafeguardClient` / `AsyncSafeguardClient`
- All `connect_*()` / `async_connect_*()` factory functions — use auth objects
- `register_signalr_username()` / `register_signalr_certificate()` — use `client.get_event_listener()`
- `a2a_get_credential()` class method — use `A2AContext`
- `WebRequestError` / `AsyncWebRequestError` — use `ApiError`
- `SafeguardException` — use `SafeguardError`
