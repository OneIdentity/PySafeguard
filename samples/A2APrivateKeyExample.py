from pysafeguard import A2AContext, SshKeyFormat

# The appliance host name or IP address
host = ""

# Path to the trusted root CA of the appliance
ca_file = ""

# The API key for private key retrieval via A2A
api_key = ""

# Path to the .pem file for certificate authentication
cert_file = ""

# Path to the corresponding .key file for certificate authentication
key_file = ""

print("Retrieving private key credentials")
with A2AContext(host, cert_file, key_file, verify=ca_file) as ctx:
    privatekey_openssh = ctx.retrieve_private_key(api_key, key_format=SshKeyFormat.OPENSSH)
    print(f"Private Key (OpenSSH): {privatekey_openssh}")

    privatekey_ssh2 = ctx.retrieve_private_key(api_key, key_format=SshKeyFormat.SSH2)
    print(f"Private Key (SSH2): {privatekey_ssh2}")

    privatekey_putty = ctx.retrieve_private_key(api_key, key_format=SshKeyFormat.PUTTY)
    print(f"Private Key (Putty): {privatekey_putty}")