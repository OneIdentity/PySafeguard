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

user = {
    "PrimaryAuthenticationProvider": {"Id": -1},
    "Name": "MyNewUser",
}
new_user_password = "MyNewUser123"

with SafeguardClient(host, auth=PasswordAuth("local", username, password), verify=ca_file) as client:
    print("Creating new user")
    result = client.post(Service.CORE, "Users", json=user).json()
    user_id = result["Id"]

    print("Setting password for user")
    client.put(Service.CORE, f"Users/{user_id}/Password", data=new_user_password)

    print("Getting newly created user")
    result = client.get(Service.CORE, f"Users/{user_id}")
    print(json.dumps(result.json(), indent=2, sort_keys=True))
