# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

import json

from pysafeguard import SafeguardClient, Service

# The appliance host name or IP address
host = ""

print("Connecting anonymously")
# WARNING: verify=False disables TLS certificate verification. This sample uses it
# so it works out of the box against a dev appliance with a self-signed certificate.
# In production, omit `verify=False` and either trust the appliance's CA via the
# REQUESTS_CA_BUNDLE environment variable or pass `verify="/path/to/ca-bundle.pem"`.
# See the "TLS Verification" section in README.md for details.
client = SafeguardClient(host, verify=False)

print("Getting status")
result = client.get(Service.NOTIFICATION, "Status")
print(json.dumps(result.json(), indent=2, sort_keys=True))

client.close()