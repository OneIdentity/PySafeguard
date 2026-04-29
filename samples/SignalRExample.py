# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

from pysafeguard import SafeguardClient, PasswordAuth

# The appliance host name or IP address
host = ""

# The user name for password authentication
username = ""

# The password for password authentication
password = ""

# Path to the trusted root CA of the appliance
ca_file = ""

with SafeguardClient(host, auth=PasswordAuth("local", username, password), verify=ca_file) as client:
    listener = client.get_event_listener()
    listener.on("AssetCreated", lambda name, body: print(f"Asset created: {name}"))

    with listener:
        listener.start()
        input("Press Enter to stop listening...")

