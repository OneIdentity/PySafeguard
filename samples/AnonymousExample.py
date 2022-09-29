from pysafeguard import *
import json

# The appliance host name or IP address
hostName = ''

print('Connecting anonymously')
connection = PySafeguardConnection(hostName, False)

print('Getting status')
result = connection.invoke(HttpMethods.GET, Services.NOTIFICATION, 'Status')
print(json.dumps(result.json(),indent=2,sort_keys=True))