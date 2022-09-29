from pysafeguard import *
import json
import time

# The appliance host name or IP address
hostName = ''

# The user name for password authentication
userName = ''

# The password for passowrd authentication
password = ''

# Path to the trusted root ca of the appliance
caFile = ''

# Path to the .pem file for certificate authentication
userCertFile = ''

# Path to the corresponding .key file for certificate authentication
userKeyFile = ''

print('Connecting to Safeguard')
connection = PySafeguardConnection(hostName, caFile)

# SignalR callback function to handle the signalR messages
def signalrcallback(results):
    print("Received SignalR event: {0}".format(results[0]['Message']))


print("Connecting to SignalR via username/password")
connection.register_signalr_username(hostName, signalrcallback, connection, userName, password)
time.sleep(30)


print("Connecting to SignalR via certifacte")
connection.register_signalr_certificate(hostName, signalrcallback, connection, userCertFile, userKeyFile)
print("wait 30 seconds to try out signalR")
time.sleep(30)


