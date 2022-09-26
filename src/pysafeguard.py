from enum import Enum

class Services(Enum):
    CORE = 1
    APPLIANCE = 2
    NOTIFICATION = 3
    A2A = 4

class HttpMethods(Enum):
    GET = 1
    POST = 2
    PUT = 3
    DELETE = 4

class A2ATypes(Enum):
    PASSWORD = 1
    PRIVATEKEY = 2

class SshKeyFormats(Enum):
    OPENSSH = 1
    SSH2 = 2
    PUTTY = 3


class PySafeguardConnection:
    # TODO: Add constants for services, web methods, etc

    #Private method
    def __execute_web_request():
        # This method will be called by invoke, connect_password, etc when making web requests
        return "not implemented yet"

    def __init__(self, host):
        self.host = host
        self.access_token = None

    def connect_password(self, user_name, password, provider):
        # TODO: rSTS integration to get an access token
        self.access_token = None

    def connect_certificate(self, cert, key, pfx, passphrase, provider):
        # TODO: rSTS logic integration to get an access token
        self.access_token = None

    def invoke(self, service, httpMethod, relativeUrl, body, parameters, additionalHeaders):
        #TODO: make web request using the provided information
        return "not implemented yet"
    
    def a2a_get_credential(self, apiKey, type, keyFormat, cert, key, passphrase):
        #TODO: get the a2a credential
        # Example:
        # let credential = await SafeguardJs._executePromise(`https://${hostName}/service/a2a/v3/Credentials?type=${type}&keyFormat=${keyFormat}`, SafeguardJs.HttpMethods.GET, null, 'json', additionalHeaders, null, null, httpsAgent);
        if apiKey == None or apiKey == "":
            raise Exception("apiKey may not be null or empty")

        if type == None or type == "":
            raise Exception("type may not be null or empty")

        if cert == None or cert == "" or key == None or key == "":
            raise Exception("A cert and key must be specified")

        if passphrase == None or passphrase == "":
            raise Exception("A passphrase must be specified")

        if keyFormat == None or keyFormat == "":
            keyFormat = SshKeyFormats.OPENSSH





    def a2a_get_credential_from_files(self, apiKey, type, keyFormat, certFile, keyFile, passphrase):
        '''(Public) Retrieves an application to application credential.
        * @param {string}              hostName    (Required) The name or ip of the safeguard appliance.
        * @param {string}              apiKey      (Required) The a2a api key.
        * @param {string}              type        (Required) The type of credential to retrieve (password, privatekey, etc).
        * @param {string}              keyFormat   (Optional) The privateKeyFormat to return (openssh, ssh2, putty, etc).
        * @param {string}              certFile    (Required) The user certificate file location in pem format.
        * @param {string}              keyFile     (Required) The user certificate's key file location in key format.
        * @param {string}              passphrase  (Required) The user certificate's passphrase.
        '''
        cert = None
        key = None

        if certFile == None or certFile == "" or keyFile == None or keyFile == "":
            raise Exception("cert path and key path must be specified.")
        else:
            f = open(certFile, 'r')
            cert = f.read()

            f = open(keyFile, 'r')
            key = f.read()
            
        return self.a2a_get_credential(apiKey, type, keyFormat, cert, key, passphrase)

    def register_signalr(self, callback):
        #TODO: register the signalr callback
        #This will require a python module with targeting https://${hostName}/service/event/signalr
        return
    