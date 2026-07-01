# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

import json

from pysafeguard import DeviceCodeAuth, DeviceCodeInfo, SafeguardClient, Service

# The appliance host name or IP address
host = ""

# Path to the trusted root CA of the appliance
ca_file = ""


def show_device_code(info: DeviceCodeInfo) -> None:
    # Displaying the verification URL and user code is the caller's
    # responsibility. The SDK never prints anything or opens a browser.
    print("To sign in, use a web browser on any device to open the page below")
    print(f"  {info.verification_uri_complete}")
    print("If the code is not pre-filled, enter it manually:")
    print(f"  Verification URL: {info.verification_uri}")
    print(f"  User code:        {info.user_code}")
    print(f"Waiting for you to authenticate (expires in {info.expires_in} seconds)...")


with SafeguardClient(host, auth=DeviceCodeAuth(show_device_code), verify=ca_file) as client:
    print("Getting me")
    result = client.get(Service.CORE, "Me")
    print(json.dumps(result.json(), indent=2, sort_keys=True))

    print("Getting login time remaining")
    minutes_left = client.token_lifetime_remaining
    print(f"Time remaining: {minutes_left}")
