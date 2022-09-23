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
        return "not implemented yet"

    def a2a_get_credential_from_files(self, apiKey, type, keyFormat, certFile, keyFile, passphrase):
        #TODO: read in the files and then call a2a_get_credential
        return a2a_get_credential()

    def register_signalr(self, callback):
        #TODO: register the signalr callback
        #This will require a python module with targeting https://${hostName}/service/event/signalr
        return
    