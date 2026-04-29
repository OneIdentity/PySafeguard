# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

import json

from pysafeguard import SafeguardClient, CertificateAuth, Service

# The appliance host name or IP address
host = ""

# Path to the trusted root CA of the appliance
ca_file = ""

# Path to the .pem file for certificate authentication
cert_file = ""

# Path to the corresponding .key file for certificate authentication
key_file = ""

with SafeguardClient(host, auth=CertificateAuth(cert_file, key_file), verify=ca_file) as client:
    print("Getting me")
    result = client.get(Service.CORE, "Me")
    print(json.dumps(result.json(), indent=2, sort_keys=True))

    print("Getting login time remaining")
    minutes_left = client.token_lifetime_remaining
    print(f"Time remaining: {minutes_left}")