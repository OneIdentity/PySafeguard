from pysafeguard import *

hostName = ""
userName = ""
password = ""
pathToCAFile = ""

print('Connecting to Safeguard')
connection = PySafeguardConnection(hostName, pathToCAFile)

print('Logging in')
connection.connect_password(userName, password)

print('Getting login time remaining')
minutes_left = connection.get_remaining_token_lifetime()
print(f'Time remaining: {minutes_left}')