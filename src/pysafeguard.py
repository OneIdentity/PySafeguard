import requests
import json
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

class A2ATypes:
    PASSWORD = "password"
    PRIVATEKEY = "privatekey"

class SshKeyFormats:
    OPENSSH = "openssh"
    SSH2 = "ssh2"
    PUTTY = "putty"

class WebRequestError(Exception):
    def __init__(self, req):
        self.req = req
        self.message = '{} {}: {} {}\n{}'.format(req.status_code,req.reason,req.request.method,req.url,req.text)
        super().__init__(self.message)

def _assemble_path(*args):
    return '/'.join(map(lambda x: str(x).strip('/'), filter(None, args)))

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

    @staticmethod
    def __execute_web_request(httpMethod, url, body, headers, verify, cert):
        dojson = 'application/json' in headers.get('content-type','').lower()
        bodytype = dict(json=body) if dojson else dict(data=body)
        with httpMethod(url, headers=headers, cert=cert, verify=verify, **bodytype) as req:
            if req.status_code >= 200 and req.status_code < 300:
                return req
            else:
                raise WebRequestError(req)

    def get_provider_id(self, name):
        req = self.invoke_web_request(HttpMethods.POST, Services.RSTS, 'UserLogin/LoginController', query=dict(redirect_uri='urn:InstalledApplication', loginRequestStep=1, response_type='token'), body='RelayState=', additionalHeaders={'Content-type':'application/x-www-form-urlencoded'})
        response = req.json()
        providers = response.get('Providers',[])
        matches = list(filter(lambda x: name == x['DisplayName'], providers))
        if matches:
            return matches[0]['Id']
        else:
            raise Exception('Unable to find Provider with DisplayName {} in\n{}'.format(name,json.dumps(providers,indent=2,sort_keys=True)))

    def connect_password(self, user_name, password, provider='local'):
        body = {
          'scope': 'rsts:sts:primaryproviderid:{}'.format(provider),
          'grant_type': 'password',
          'username': user_name,
          'password': password
        }
        req = self.invoke_web_request(HttpMethods.POST, Services.RSTS, 'oauth2/token', body=body)
        if req.status_code == 200 and 'application/json' in req.headers.get('Content-type',''):
            data = req.json()
            req = self.invoke_web_request(HttpMethods.POST, Services.CORE, 'Token/LoginResponse', body=dict(StsAccessToken=data.get('access_token')))
            if req.status_code == 200 and 'application/json' in req.headers.get('Content-type',''):
                data = req.json()
                self.UserToken = data.get('UserToken')
                self.headers.update(Authorization='Bearer {}'.format(self.UserToken))
            else:
                raise WebRequestError(req)
        else:
            raise WebRequestError(req)

    def connect_certificate(self, provider='certificate'):
        body = {
          'scope': 'rsts:sts:primaryproviderid:{}'.format(provider),
          'grant_type': 'client_credentials'
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
                raise WebRequestError(req)
        else:
            raise WebRequestError(req)

    def invoke_web_request(self, httpMethod, httpService, endpoint=None, query={}, body=None, additionalHeaders={}, host=None):
        url = _assemble_url(host or self.host, _assemble_path(httpService, self.apiVersion if httpService != Services.RSTS else '', endpoint), query)
        merged_headers = _merge_idict(self.headers, additionalHeaders)
        return PySafeguardConnection.__execute_web_request(httpMethod, url, body, merged_headers, **self.req_globals)

    @staticmethod
    def a2a_get_credential(host, apiKey, a2aType, keyFormat, cert, key, apiVersion='v4', verify=True):
        if not apiKey:
            raise Exception("apiKey may not be null or empty")

        if not a2aType:
            raise Exception("type may not be null or empty")
        
        if not cert and not key:
            raise Exception("cert path and key path may not be null or empty")

        if not keyFormat:
            keyFormat = SshKeyFormats.OPENSSH

        header = {
            'Authorization': 'A2A {}'.format(apiKey)
        }
        query = {
            'type': a2aType,
            'keyFormat': keyFormat
        }
        credentials = PySafeguardConnection.__execute_web_request(HttpMethods.GET, _assemble_url(host, _assemble_path(Services.A2A, apiVersion, "Credentials"), query), body={}, headers=header, verify=verify, cert=(cert, key))
        if credentials.status_code != 200:
            raise WebRequestError(credentials)
        return credentials.json()

    def register_signalr(self, callback):
        #TODO: register the signalr callback
        #This will require a python module with targeting https://${hostName}/service/event/signalr
        return
    
