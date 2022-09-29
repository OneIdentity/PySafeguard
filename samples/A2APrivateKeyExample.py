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


print('Retrieving private key credentials')

privatekey_openssh = PySafeguardConnection.a2a_get_credential(hostName, apiKey, userCertFile, userKeyFile, caFile, A2ATypes.PRIVATEKEY)
print(f'Private Key (OpenSSH): {privatekey_openssh}')

privatekey_ssh2 = PySafeguardConnection.a2a_get_credential(hostName, apiKey, userCertFile, userKeyFile, caFile, A2ATypes.PRIVATEKEY, SshKeyFormats.SSH2)
print(f'Private Key (SSH2): {privatekey_ssh2}')

privatekey_putty = PySafeguardConnection.a2a_get_credential(hostName, apiKey, userCertFile, userKeyFile, caFile, A2ATypes.PRIVATEKEY, SshKeyFormats.PUTTY)
print(f'Private Key (Putty): {privatekey_putty}')