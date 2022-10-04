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
one of the `connect_*()` methods to establish a connection to Safeguard, then
you can call `invoke()` multiple times using the same authenticated connection.

PySafeguard also provides an easy way to call Safeguard A2A from Python. The A2A service requires client certificate authentication for retrieving passwords for application integration. When Safeguard A2A is properly configured, specified passwords can be retrieved with a single method call without requiring access request workflow approvals. Safeguard A2A is protected by API keys and IP restrictions in addition to client certificate authentication.

PySafeguard includes an SDK for listening to Safeguard's powerful, real-time event notification system. Safeguard provides role-based event notifications via SignalR to subscribed clients. If a Safeguard user is an Asset Administrator events related to the creation, modification, or deletion of Assets and Asset Accounts will be sent to that user. When used with a certificate user, this provides an opportunity for reacting programmatically to any data modification in Safeguard. Events are also supported for access request workflow and for A2A password changes.

## Installation

This Python module is published to the [PyPi registry](https://pypi.org/project/pysafeguard) to make it as easy as possible to install.

```Bash
> pip install pysafeguard
```

## Dependencies
pysafeguard uses the python requests module, which will need to be installed prior to using pysafeguard

```Bash
> pip install requests
```
In addition if you will be using the SignalR functionality you will need to install SignalR Core client module.  SignalR Core client is only required if using the SignalR functionality

```Bash
> pip install signalrcore
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

- Environment variable providing path to certificates</li>

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
  
- Use the `verify` option when creating the `PySafeguardConnection`</li>

  See examples below for utilizing this method.  While `verify` can be
  used to disable security checking this is not recommended.

> **Note**  
> The WEBSOCKET_CLIENT_CA_BUNDLE environment variable is only necessary
> when working with SignalR.

## Getting Started

A simple code example for calling the Safeguard API with username and password authentication through the local Safeguard STS:

```Python
from pysafeguard import *

connection = PySafeguardConnection('safeguard.sample.corp', 'ssl/pathtoca.pem')
connection.connect_password('Admin','Admin123')
me = connection.invoke(HttpMethods.GET, Services.CORE, 'Me', query=dict(fields='DisplayName'))
print('Connected to Safeguard as %s' % me.json()['DisplayName'])
```

Password authentication to an external provider is as follows:
(Sample can be found <a href="samples\PasswordExternalExample.py">here</a>.)

```Python
from pysafeguard import *

connection = PySafeguardConnection('safeguard.sample.corp', 'ssl/pathtoca.pem')
connection.connect_password('Admin','Admin123', 'myexternalprovider')
```


Client certificate authentication is also available. This can be done using PEM and KEY file.

```Python
from pysafeguard import *

connection = PySafeguardConnection('safeguard.sample.corp', 'ssl/pathtoca.pem')
connection.connect_certificate('ssl/pathtocertuser.pem', 'ssl/pathtocertuser.key')
```

> **Note**  
> Password protected certificates are not currently supported in PySafeguard.

Client certificate authentication to an external provider is also available. This can be done using PEM and KEY file.

```Python
from pysafeguard import *

connection = PySafeguardConnection('safeguard.sample.corp', 'ssl/pathtoca.pem')
connection.connect_certificate('ssl/pathtocertuser.pem', 'ssl/pathtocertuser.key', 'myexternalprovider')
```


A connection can also be made anonymously and without verifying the appliance certificate.

```Python
from pysafeguard import *

connection = PySafeguardConnection('safeguard.sample.corp', False)
system_time = connection.invoke(HttpMethods.GET, Services.APPLIANCE, 'SystemTime')
```

Authentication is also possible using an existing Safeguard API token:

```Python
from pysafeguard import *

connection = PySafeguardConnection('safeguard.sample.corp', 'ssl/pathtoca.pem')
connection.connect_token(myApiToken)
```
> **Note**  
> Two-factor authentication is not currently supported in PySafeguard.

## Getting Started With A2A

Once you have configured your A2A registration in Safeguard you can retrieve an A2A password or private key using a certificate and api key.

To retrieve a password via A2A:

```Python
from pysafeguard import *

password = PySafeguardConnection.a2a_get_credential('safeguard.sample.corp', 'myapikey', 'ssl/pathtocertuser.pem', 'ssl/pathtocertuser.key', 'ssl/pathtoca.pem')
```

To retrieve a private key in OpenSSH format via A2A:

```Python
from pysafeguard import *

privatekey = PySafeguardConnection.a2a_get_credential('safeguard.sample.corp', 'myapikey', 'ssl/pathtocertuser.pem', 'ssl/pathtocertuser.key', 'ssl/pathtoca.pem', A2ATypes.PRIVATEKEY)
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

Sample can be found <a href="samples\AnonymousExample.py">here</a>.

```Python
from pysafeguard import *

connection = PySafeguardConnection('safeguard.sample.corp', False)
result = connection.invoke(HttpMethods.GET, Services.NOTIFICATION, 'Status')
print(json.dumps(result.json(),indent=2,sort_keys=True))
```

#### Get remaining access token lifetime

Sample can be found <a href="samples\PasswordExample.py">here</a>.

```Python
from pysafeguard import *

connection = PySafeguardConnection('safeguard.sample.corp', 'ssl/pathtoca.pem')
connection.connect_password('username', 'password')
minutes_left = connection.get_remaining_token_lifetime()
print(minutes_left)
```

#### Register for SignalR events

To use the SignalR functionality, you will need to install the python SignalR Core client module

```Bash
> pip install signalrcore
```

Sample can be found <a href="samples\SignalRExample.py">here</a>.

```Python
from pysafeguard import *

connection = PySafeguardConnection(hostName, caFile)

# SignalR callback function to handle the signalR messages
def signalrcallback(results):
    print("Received SignalR event: {0}".format(results[0]['Message']))

print("Connecting to SignalR via username/password")
connection.register_signalr_username(connection, signalrcallback, userName, password)

print("Connecting to SignalR via certifacte")
connection.register_signalr_certificate(connection, signalrcallback, userCertFile, userKeyFile)
```
> **Note**  
> Password protected certificates are not currently supported in PySafeguard.

#### Create a New User and Set the Password

Sample can be found <a href="samples\NewUserExample.py">here</a>.

```Python
from pysafeguard import *
import json

user = {
    'PrimaryAuthenticationProvider': { 'Id': -1 },
    'Name': 'MyNewUser'
}
password = 'MyNewUser123'
connection = PySafeguardConnection('safeguard.sample.corp', 'ssl/pathtoca.pem')
connection.connect_password('username', 'password')
result = connection.invoke(HttpMethods.POST, Services.CORE, 'Users', body=user).json()
userId = result.get('Id')
connection.invoke(HttpMethods.PUT, Services.CORE, f'Users/{userId}/Password', body=password)
```
