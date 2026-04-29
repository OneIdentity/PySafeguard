# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

from pysafeguard import SafeguardClient, PkceAuth

# The appliance host name or IP address
host = ""

# The user name for PKCE authentication
username = ""

# The password for PKCE authentication
password = ""

# Path to the trusted root CA of the appliance
ca_file = ""


def on_asset_created(name: str, body: str) -> None:
    print(f"Asset created: {name}\n{body}")


def on_asset_modified(name: str, body: str) -> None:
    print(f"Asset modified: {name}\n{body}")


with SafeguardClient(host, auth=PkceAuth("local", username, password), verify=ca_file) as client:
    listener = client.get_persistent_event_listener()
    listener.on("AssetCreated", on_asset_created)
    listener.on("AssetModified", on_asset_modified)

    with listener:
        listener.start()
        print("Persistent listener started (auto-reconnects on disconnect)")
        input("Press Enter to stop listening...")
