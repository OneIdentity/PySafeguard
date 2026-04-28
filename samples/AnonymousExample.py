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