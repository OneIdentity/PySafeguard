from pysafeguard import A2AContext

# The appliance host name or IP address
host = ""

# Path to the trusted root CA of the appliance
ca_file = ""

# The API key for password retrieval via A2A
api_key = ""

# Path to the .pem file for certificate authentication
cert_file = ""

# Path to the corresponding .key file for certificate authentication
key_file = ""

print("Retrieving password credential")
with A2AContext(host, cert_file, key_file, verify=ca_file) as ctx:
    password = ctx.retrieve_password(api_key)
    print(f"Password: {password}")