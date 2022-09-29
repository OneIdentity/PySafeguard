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
        self.headers = CaseInsensitiveDict({'Accept':'application/json'})

    @staticmethod
    def __execute_web_request(httpMethod, url, body, headers, verify, cert):
        bodystyle = dict(data=body)
        if body and httpMethod in [HttpMethods.POST, HttpMethods.PUT] and not headers.get('content-type'):
            bodystyle = dict(json=body)
            headers = _merge_idict(headers, {'Content-type':'application/json'})
        with httpMethod(url, headers=headers, cert=cert, verify=verify, **bodystyle) as req:
            if req.status_code >= 200 and req.status_code < 300:
                return req
            else:
                raise WebRequestError(req)

    @staticmethod
    def a2a_get_credential(host, apiKey, cert, key, verify=True, a2aType=A2ATypes.PASSWORD, keyFormat=SshKeyFormats.OPENSSH, apiVersion='v4'):
        if not apiKey:
            raise Exception("apiKey may not be null or empty")

        if not cert and not key:
            raise Exception("cert path and key path may not be null or empty")

        header = {
            'Authorization': f'A2A {apiKey}'
        }
        query = _merge_dict(dict(type=a2aType), dict(keyFormat=keyFormat) if a2aType == A2ATypes.PRIVATEKEY else {})
        credential = PySafeguardConnection.__execute_web_request(HttpMethods.GET, _assemble_url(host, _assemble_path(Services.A2A, apiVersion, "Credentials"), query), body={}, headers=header, verify=verify, cert=(cert, key))
        if credential.status_code != 200:
            raise WebRequestError(credential)
        return credential.json()

    def get_provider_id(self, name):
        req = self.invoke(HttpMethods.POST, Services.RSTS, 'UserLogin/LoginController', query=dict(redirect_uri='urn:InstalledApplication', loginRequestStep=1, response_type='token'), body='RelayState=', additionalHeaders={'Content-type':'application/x-www-form-urlencoded'})
        response = req.json()
        providers = response.get('Providers',[])
        matches = list(filter(lambda x: name == x['DisplayName'], providers))
        if matches:
            return matches[0]['Id']
        else:
            raise Exception('Unable to find Provider with DisplayName {} in\n{}'.format(name,json.dumps(providers,indent=2,sort_keys=True)))

    def connect(self, body, *args, **kwargs):
        req = self.invoke(HttpMethods.POST, Services.RSTS, 'oauth2/token', body=body, *args, **kwargs)
        if req.status_code == 200 and 'application/json' in req.headers.get('Content-type',''):
            data = req.json()
            req = self.invoke(HttpMethods.POST, Services.CORE, 'Token/LoginResponse', body=dict(StsAccessToken=data.get('access_token')))
            if req.status_code == 200 and 'application/json' in req.headers.get('Content-type',''):
                data = req.json()
                self.connect_token(data.get('UserToken'))
            else:
                raise WebRequestError(req)
        else:
            raise WebRequestError(req)
        return self.UserToken

    def connect_password(self, user_name, password, provider='local'):
        body = {
          'scope': 'rsts:sts:primaryproviderid:{}'.format(provider),
          'grant_type': 'password',
          'username': user_name,
          'password': password
        }
        return self.connect(body)

    def connect_certificate(self, certFile, keyFile, provider='certificate'):
        body = {
          'scope': 'rsts:sts:primaryproviderid:{}'.format(provider),
          'grant_type': 'client_credentials'
        }
        return self.connect(body,cert=(certFile,keyFile))

    def connect_token(self, token):
        self.UserToken = token
        self.headers.update(Authorization='Bearer {}'.format(self.UserToken))

    def invoke(self, httpMethod, httpService, endpoint=None, query={}, body=None, additionalHeaders={}, host=None, cert=None):
        url = _assemble_url(host or self.host, _assemble_path(httpService, self.apiVersion if httpService != Services.RSTS else '', endpoint), query)
        merged_headers = _merge_idict(self.headers, additionalHeaders)
        return PySafeguardConnection.__execute_web_request(httpMethod, url, body, merged_headers, **_merge_dict(self.req_globals, cert=cert))

    def get_remaining_token_lifetime(self):
        req = self.invoke(HttpMethods.GET, Services.APPLIANCE, 'SystemTime')
        return req.headers.get('X-tokenlifetimeremaining')

    def register_signalr(host, callback, options):
        from signalrcore.hub_connection_builder import HubConnectionBuilder
        import logging
        if ( callback  == None or callback == ""):
            raise Exception("A callback must be specified to register for the SignalR events.")
        server_url = 'https://{0}/service/event/signalr'.format(host)
        hub_connection = HubConnectionBuilder() \
        .with_url(server_url, options=options) \
        .with_automatic_reconnect({
           "type": "raw",
           "keep_alive_interval": 10,
           "reconnect_interval": 10,
           "max_attempts": 5
        }).build()

        hub_connection.on("ReceiveMessage", callback)
        hub_connection.on("NotifyEventAsync", callback)
        hub_connection.on_open(lambda: print("in on_open callback: connection opened and handshake received ready to send messages"))
        hub_connection.on_close(lambda: print("in on_close callback: connection closed"))
        hub_connection.start()

    @staticmethod
    def register_signalr_username(host, callback, conn, username, password):
        options = options={"access_token_factory": lambda: conn.connect_password(username, password)}
        PySafeguardConnection.register_signalr(host, callback, options)

    @staticmethod
    def register_signalr_certificate(host, callback, conn, certfile, keyfile):
        print("in cert")
        options = options={"access_token_factory": lambda: conn.connect_certificate(certfile, keyfile, provider="certificate")}
        PySafeguardConnection.register_signalr(host, callback, options)
    
