from pysafeguard import *
from src.pysafeguard import A2ATypes, SshKeyFormats

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


print('Retrieving api key secret credentials')

apiKeys_json = PySafeguardConnection.a2a_get_credential(hostName, apiKey, userCertFile, userKeyFile, caFile, A2ATypes.APIKEYSECRET)
print(f'API Key JSON: {apiKeys_json}')

apiKeys = json.loads(apiKeys_json)
print(f'API Keys Count: {len(apiKeys)}')

for apiKey in apiKeys:
    printf(f'Client Id: {apiKey.ClientId}')
    printf(f'Client Secret: {apiKey.ClientSecret}')