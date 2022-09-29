from pysafeguard import *

# The appliance host name or IP address
hostName = ''

# Path to the trusted root ca of the appliance
caFile = ''

# The API Key for private key retrieval via A2A
apiKey = ''

# Path to the .pem file for certificate authentication
userCertFile = ''

# Path to the corresponding .key file for certificate authentication
userKeyFile = ''

print('Retrieving password credential')
password = PySafeguardConnection.a2a_get_credential(hostName, apiKey, userCertFile, userKeyFile, caFile)
print(f'Password: {password}')