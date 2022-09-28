# PySafeguard
One Identity Safeguard Python SDK

-----------

<p align="center">
<i>Check out our <a href="samples">sample projects</a> to get started with your own custom integration to Safeguard!</i>
</p>

-----------

## Support

One Identity open source projects are supported through [One Identity GitHub issues](https://github.com/OneIdentity/PySafeguard/issues) and the [One Identity Community](https://www.oneidentity.com/community/). This includes all scripts, plugins, SDKs, modules, code snippets or other solutions. For assistance with any One Identity GitHub project, please raise a new Issue on the [One Identity GitHub project](https://github.com/OneIdentity/PySafeguard/issues) page. You may also visit the [One Identity Community](https://www.oneidentity.com/community/) to ask questions.  Requests for assistance made through official One Identity Support will be referred back to GitHub and the One Identity Community forums where those requests can benefit all users.

## Introduction

All functionality in Safeguard is available via the Safeguard API. There is
nothing that can be done in the Safeguard UI that cannot also be performed
using the Safeguard API programmatically.

PySafeguard is provided to facilitate calling the Safeguard API from Python.
It is meant to remove the complexity of dealing with authentication via
Safeguard's embedded secure token service (STS). The basic usage is to call
`connect()` to establish a connection to Safeguard, then you can call
`invoke_web_request()` multiple times using the same authenticated connection.

PySafeguard also provides an easy way to call Safeguard A2A from Python. The A2A service requires client certificate authentication for retrieving passwords for application integration. When Safeguard A2A is properly configured, specified passwords can be retrieved with a single method call without requiring access request workflow approvals. Safeguard A2A is protected by API keys and IP restrictions in addition to client certificate authentication.

PySafeguard includes an SDK for listening to Safeguard's powerful, real-time event notification system. Safeguard provides role-based event notifications via SignalR to subscribed clients. If a Safeguard user is an Asset Administrator events related to the creation, modification, or deletion of Assets and Asset Accounts will be sent to that user. When used with a certificate user, this provides an opportunity for reacting programmatically to any data modification in Safeguard. Events are also supported for access request workflow and for A2A password changes.

## Installation

This Python module is published to the [PyPi registry](https://pypi.org/manage/project/pysafeguard/releases/) to make it as easy as possible to install.

```Bash
> pip install pysafeguard
```

## Getting Started

A simple code example for calling the Safeguard API with username and password authentication through the local Safeguard STS:

```Python
from pysafeguard import *

conn = PySafeguardConnection('safeguard.sample.corp', 'ssl/pathtocertuser.pem')
conn.connect_password('Admin','Admin123')
req = conn.invoke(HttpMethods.GET,Services.CORE,'Me')
```

Password authentication to an external provider is as follows:

```Python
#TODO: Update for latest code
from pysafeguard import *

conn = PySafeguardConnection('safeguard.sample.corp', 'ssl/pathtocertuser.pem')
conn.connect_password('Admin','Admin123', 'myexternalprovider')
req = conn.invoke(HttpMethods.GET,Services.CORE,'Me')
```

Client certificate authentication is also available. This can be done either using a PFX certificate file or a PEM and KEY.

```Python
#TODO: Update for latest code
from pysafeguard import *

conn = PySafeguardConnection('safeguard.sample.corp', 'ssl/ca.pem')
conn.connect_certificate('ssl/certificateuser.pem', 'ssl/certificateuser.key)
```

```Python
#TODO: Update for latest code
from pysafeguard import *

conn = PySafeguardConnection('safeguard.sample.corp', 'ssl/ca.pem')
conn.connect_certificate(null, null, 'ssl/certificateuser.pfx')
```

> **Note**  
> Password protected certificates are not currently supported in PySafeguard.

Client certificate authentication to an external provider is also available. This can again be done either using a PFX certificate file or a PEM and KEY.

```Python
#TODO: Update for latest code
from pysafeguard import *

conn = PySafeguardConnection('safeguard.sample.corp', 'ssl/ca.pem')
conn.connect_certificate('ssl/certificateuser.pem', 'ssl/certificateuser.key', None, 'myexternalprovider')
```

```Python
#TODO: Update for latest code
from pysafeguard import *

conn = PySafeguardConnection('safeguard.sample.corp', 'ssl/ca.pem')
conn.connect_certificate(None, None, 'ssl/certificateuser.pfx', 'myexternalprovider')
```

A connection can also be made anonymously 

```Python
from pysafeguard import *

conn = PySafeguardConnection('safeguard.sample.corp', False)
```

Authentication is also possible using an existing Safeguard API token:

```Python
#TODO: Update for latest code
from pysafeguard import *

apiToken = get_token_somehow()
conn = PySafeguardConnection('safeguard.sample.corp')
conn.set_user_token(apiToken)
```
> **Note**  
> Two-factor authentication is not currently supported in PySafeguard.

## Getting Started With A2A

Once you have configured your A2A registration in Safeguard you can retrieve an A2A password or private key using a certificate and api key.

To retrieve a password via A2A:

```Python 
from pysafeguard import *

password = PySafeguardConnection.a2a_get_credential('myhost', 'myapikey', A2ATypes.PASSWORD, None, 'ssl/pathtocertuser.crt, ssl/pathtocertuser.key, ssl/pathtocertuser.pem)

```

To retrieve a private key via A2A:

```Python
from pysafeguard import *

privatekey = PySafeguardConnection.a2a_get_credential('myhost', 'myapikey', A2ATypes.PASSWORD, SshKeyFormats.OPENSSH, 'ssl/pathtocertuser.crt, ssl/pathtocertuser.key, ssl/pathtocertuser.pem)
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

Most functionality is in the core service as mentioned above.  The notification service
provides read-only information for status, etc.

#### Anonymous Call for Safeguard Status

Sample can be found <a href="samples\AnonymousExample">here</a>.

```Python
#TODO: give example targeting
# PySafeguard.Services.NOTIFICATION, PySafeguard.HttpMethods.GET, 'v3/Status'
```

#### Get remaining access token lifetime

Sample can be found <a href="samples\AccessTokenLifetime">here</a>.

```Python
#TODO: Decide if we want to add this functionality
```

#### Register for SignalR events

Sample can be found <a href="samples\SignalRExample">here</a>.

```Python
#TODO: give example of signalr
```

#### Create a New User and Set the Password

Sample can be found <a href="samples\NewUserExample">here</a>.

```Python
#TODO: Give example of creating a new user and setting the user's password
```
