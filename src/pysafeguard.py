import requests
from requests.structures import CaseInsensitiveDict
from urllib.parse import urlunparse,urlencode
from enum import Enum

class Services:
    CORE = 'service/core'
    APPLIANCE = 'service/appliance'
    NOTIFICATION = 'service/notification'
    A2A = 'service/a2a'
    EVENT = 'service/event'
    RSTS = 'RSTS'

class HttpMethods:
    GET = requests.get
    POST = requests.post
    PUT = requests.put
    DELETE = requests.delete

class A2ATypes(Enum):
    PASSWORD = 1
    PRIVATEKEY = 2

class SshKeyFormats(Enum):
    OPENSSH = 1
    SSH2 = 2
    PUTTY = 3

def _assemble_path(*args):
    return '/'.join(map(lambda x: str(x).strip('/'), args))

def _assemble_url(netloc='',path='',query={},fragment='',scheme='https'):
    return urlunparse((scheme,netloc,path,'',urlencode(query,True),fragment))

def _create_merging_thing(cls):
    def _inner_merge(*args,**kwargs):
        return cls(sum(map(lambda x: list(x.items()), args+(kwargs,)),[]))
    return _inner_merge

_merge_dict = _create_merging_thing(dict)
_merge_idict = _create_merging_thing(CaseInsensitiveDict)

class PySafeguardConnection:
    # TODO: Add constants for services, web methods, etc

    def __init__(self, host, verify=True):
        self.host = host
        self.UserToken = None
        self.apiVersion = 'v4'
        self.req_globals = dict(verify=verify,cert=None)
        self.headers = CaseInsensitiveDict({'Accept':'application/json','Content-type':'application/json'})

    def __execute_web_request(self, httpMethod, httpService, endpoint, query, body, headers):
        url = _assemble_url(self.host, _assemble_path(httpService, self.apiVersion if httpService != Services.RSTS else '', endpoint), query)
        with httpMethod(url, json=body, headers=_merge_idict(self.headers, headers), **self.req_globals) as req:
            if req.status_code >= 200 and req.status_code < 300:
                return req
            else:
                raise Exception('{} {}: {} {}\n{}'.format(req.status_code,req.reason,req.request.method,req.url,req.text))

    def connect_password(self, user_name, password, provider='local'):
        body = {
          'scope': 'rsts:sts:primaryproviderid:{}'.format(provider),
          'grant_type': 'password',
          'username': user_name,
          'password': password
        }
        req = self.__execute_web_request(HttpMethods.POST,Services.RSTS,'oauth2/token',{},body,{})
        if req.status_code == 200 and 'application/json' in req.headers.get('Content-type',''):
            data = req.json()
            req = self.__execute_web_request(HttpMethods.POST,Services.CORE,'Token/LoginResponse',{},dict(StsAccessToken=data.get('access_token')),{})
            if req.status_code == 200 and 'application/json' in req.headers.get('Content-type',''):
                data = req.json()
                self.UserToken = data.get('UserToken')
                self.headers.update(Authorization='Bearer {}'.format(self.UserToken))
            else:
                raise Exception('{} {}: {} {}\n{}'.format(req.status_code,req.reason,req.request.method,req.url,req.text))
        else:
            raise Exception('{} {}: {} {}\n{}'.format(req.status_code,req.reason,req.request.method,req.url,req.text))

    def connect_certificate(self, cert_file, key_file, pfx_file, passphrase, provider='certificate'):
        # TODO: rSTS logic integration to get an access token
        self.access_token = None

    def invoke(self, httpMethod, httpService, endpoint=None, query={}, body=None, additionalHeaders={}):
        return self.__execute_web_request(httpMethod, httpService, endpoint, query, body, additionalHeaders)

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
    
