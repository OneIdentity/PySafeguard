from pysafeguard import *
import json

# The appliance host name or IP address
hostName = ''

# The user name for password authentication
userName = ''

# The password for password authentication
password = ''

# Path to the trusted root ca of the appliance
caFile = ''

print('Connecting to Safeguard')
connection = PySafeguardConnection(hostName, caFile)

print('Logging in')
connection.connect_password(userName, password)

print('Getting me')
result = connection.invoke(HttpMethods.GET, Services.CORE, 'Me')
print(json.dumps(result.json(),indent=2,sort_keys=True))

print('Getting login time remaining')
minutes_left = connection.get_remaining_token_lifetime()
print(f'Time remaining: {minutes_left}')