from pysafeguard import A2AContext, A2AType

# The appliance host name or IP address
host = ""

# Path to the trusted root CA of the appliance
ca_file = ""

# The API key for API key secret retrieval via A2A
api_key = ""

# Path to the .pem file for certificate authentication
cert_file = ""

# Path to the corresponding .key file for certificate authentication
key_file = ""

print("Retrieving API key secret credentials")
with A2AContext(host, cert_file, key_file, verify=ca_file) as ctx:
    api_key_secret = ctx.retrieve_api_key_secret(api_key)
    print(f"API Key Secret: {api_key_secret}")
