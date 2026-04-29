# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

import json

from pysafeguard import SafeguardClient, Service

# The appliance host name or IP address
host = ""

print("Connecting anonymously")
client = SafeguardClient(host, verify=False)

print("Getting status")
result = client.get(Service.NOTIFICATION, "Status")
print(json.dumps(result.json(), indent=2, sort_keys=True))

client.close()