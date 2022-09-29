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

user = {
    'PrimaryAuthenticationProvider': { 'Id': -1 },
    'Name': 'MyNewUser'
}
password = 'MyNewUser123'

print('Connecting to Safeguard')
connection = PySafeguardConnection(hostName, caFile)

print('Logging in')
connection.connect_password(userName, password)

print('Creating new user')
result = connection.invoke(HttpMethods.POST, Services.CORE, 'Users', body=user).json()

# Gets the ID of newly created user
userId = result.get('Id')

print('Creating password for user')
connection.invoke(HttpMethods.PUT, Services.CORE, f'Users/{userId}/Password', body=password)

print('Getting newly created user')
result = connection.invoke(HttpMethods.GET, Services.CORE, f'Users/{userId}')
print(json.dumps(result.json(),indent=2,sort_keys=True))
