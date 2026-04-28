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

# The provider name or ID for external password authentication
external_provider = ""

with SafeguardClient(host, auth=PasswordAuth(external_provider, username, password), verify=ca_file) as client:
    print("Getting me")
    result = client.get(Service.CORE, "Me")
    print(json.dumps(result.json(), indent=2, sort_keys=True))

    print("Getting login time remaining")
    minutes_left = client.token_lifetime_remaining
    print(f"Time remaining: {minutes_left}")