from pysafeguard import *

# The appliance host name or IP address
hostName = ''

# The user name for password authentication
userName = ''

# The password for passowrd authentication
password = ''

# Path to the trusted root ca of the appliance
pathToCAFile = ''

print('Connecting to Safeguard')
connection = PySafeguardConnection(hostName, pathToCAFile)

print('Logging in')
connection.connect_password(userName, password)

print('Getting login time remaining')
minutes_left = connection.get_remaining_token_lifetime()
print(f'Time remaining: {minutes_left}')