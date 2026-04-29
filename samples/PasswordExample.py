# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

import json

from pysafeguard import SafeguardClient, PasswordAuth, Service

# The appliance host name or IP address
host = ""

# The user name for password authentication
username = ""

# The password for password authentication
password = ""

# Path to the trusted root CA of the appliance
ca_file = ""

with SafeguardClient(host, auth=PasswordAuth("local", username, password), verify=ca_file) as client:
    print("Getting me")
    result = client.get(Service.CORE, "Me")
    print(json.dumps(result.json(), indent=2, sort_keys=True))

    print("Getting login time remaining")
    minutes_left = client.token_lifetime_remaining
    print(f"Time remaining: {minutes_left}")