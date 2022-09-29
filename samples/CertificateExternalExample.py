from pysafeguard import *
import json

# The appliance host name or IP address
hostName = ''

# Path to the trusted root ca of the appliance
caFile = ''

# Path to the .pem file for certificate authentication
userCertFile = ''

# Path to the corresponding .key file for certificate authentication
userKeyFile = ''

# The provider name or ID for external password authentication
externalProvider = ''

print('Connecting to Safeguard')
connection = PySafeguardConnection(hostName, caFile)

print('Getting external provider')
external = connection.get_provider_id(externalProvider)

print('Logging in')
connection.connect_certificate(userCertFile, userKeyFile, external)

print('Getting me')
result = connection.invoke(HttpMethods.GET, Services.CORE, 'Me')
print(json.dumps(result.json(),indent=2,sort_keys=True))

print('Getting login time remaining')
minutes_left = connection.get_remaining_token_lifetime()
print(f'Time remaining: {minutes_left}')