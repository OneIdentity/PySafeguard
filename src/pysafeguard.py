import requests
import os
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

    def __init__(self, host, verify=True, apiVersion='v4'):
        """Initialize a Safeguard connection object

        Arguments:
        host -- the appliance hostname
        verify -- A path to a file with CA certificate information or 
                  False to disable verification
        apiVersion -- The version of the API with which to connect
        """
        self.host = host
        self.UserToken = None
        self.apiVersion = apiVersion
        self.req_globals = dict(verify=verify,cert=None)
        self.headers = CaseInsensitiveDict({'Accept':'application/json'})

    @staticmethod
    def __execute_web_request(httpMethod, url, body, headers, verify, cert):
        bodystyle = dict(data=body)
        if body and httpMethod in [HttpMethods.POST, HttpMethods.PUT] and not headers.get('content-type'):
            bodystyle = dict(json=body)
            headers = _merge_idict(headers, {'Content-type':'application/json'})
        with httpMethod(url, headers=headers, cert=cert, verify=verify, **bodystyle) as req:
            return req

    @staticmethod
    def a2a_get_credential(host, apiKey, cert, key, verify=True, a2aType=A2ATypes.PASSWORD, keyFormat=SshKeyFormats.OPENSSH, apiVersion='v4'):
        '''(Public) Retrieves an application to application credential.

        Keyword arguments:
        host -- Name or ip of the safeguard appliance.
        apiKey -- A2A api key.
        cert -- Path to the user certificate in pem format.
        key -- Path to the user certificate's key in key format.
        verify -- A path to a file with CA certificate information or False to disable verification
        a2aType -- Type of credential to retrieve (password, privatekey). Defaults to password.
        keyFormat -- The privateKeyFormat to return (openssh, ssh2, putty). Defaults to openshh.
        apiVersion -- API version to use. Defaults to v4.
        '''
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
        """Get an authentication provider by name to use when authenticating

        Arguments:
        name -- The name of a configured provider

        Returns:
        A string value which is the ID of a configured provider
        """
        req = self.invoke(HttpMethods.POST, Services.RSTS, 'UserLogin/LoginController', query=dict(redirect_uri='urn:InstalledApplication', loginRequestStep=1, response_type='token'), body='RelayState=', additionalHeaders={'Content-type':'application/x-www-form-urlencoded'})
        response = req.json()
        providers = response.get('Providers',[])
        matches = list(filter(lambda x: name == x['DisplayName'], providers))
        if matches:
            return matches[0]['Id']
        else:
            raise Exception('Unable to find Provider with DisplayName {} in\n{}'.format(name,json.dumps(providers,indent=2,sort_keys=True)))

    def __connect(self, body, *args, **kwargs):
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

    def connect_password(self, username, password, provider='local'):
        """Obtain a token using username and password - used when connecting

        Arguments:
        username -- The username of an authorized user
        password -- The password for the user
        provider -- An authentication provider ID associated with user 
        """
        body = {
          'scope': 'rsts:sts:primaryproviderid:{}'.format(provider),
          'grant_type': 'password',
          'username': username,
          'password': password
        }
        self.__connect(body)

    def connect_certificate(self, certFile, keyFile, provider='certificate'):
        """Obtain a token using certificate and key file - used when connecting

        Arguments:
        certFile -- path to the client certificate
        keyFile -- path to the key for the certificate
        provider -- An authentication provider ID associated with certificate
        """
        body = {
          'scope': 'rsts:sts:primaryproviderid:{}'.format(provider),
          'grant_type': 'client_credentials'
        }
        self.__connect(body,cert=(certFile,keyFile))

    def connect_token(self, token):
        """Use an existing token""

        Arguments:
        token -- The user token
        """
        self.UserToken = token
        self.headers.update(Authorization='Bearer {}'.format(self.UserToken))

    def invoke(self, httpMethod, httpService, endpoint=None, query={}, body=None, additionalHeaders={}, host=None, cert=None, apiVersion=None):
        """Invoke a web request against the Safeguard API

        Arguments:
        httpMethod -- One of the predefined HttpMethods
        httpService -- One of the predefined Services
        endpoint -- The path of an API endpoint to use (e.g. 'Users', 'Assets')
        query -- A dictionary of query parameters that are added to endpoint
        body -- The data that is sent in the request.  Usually a dictionary.
        headers -- Headers that are added to the request
        host -- The host to which the request is made (useful for clusters)
        cert -- A 2-tuple of the certificate and key
        apiVersion -- Which version of the API to use in this request

        Returns:
        Request Response object.
        """
        url = _assemble_url(host or self.host, _assemble_path(httpService, (apiVersion or self.apiVersion) if httpService != Services.RSTS else '', endpoint), query)
        merged_headers = _merge_idict(self.headers, additionalHeaders)
        return PySafeguardConnection.__execute_web_request(httpMethod, url, body, merged_headers, **_merge_dict(self.req_globals, cert=cert))

    def get_remaining_token_lifetime(self):
        """Get the remaining time left on the access token

        Returns:
        integer value in minutes
        """
        req = self.invoke(HttpMethods.GET, Services.APPLIANCE, 'SystemTime')
        return req.headers.get('X-tokenlifetimeremaining')

    @staticmethod
    def __register_signalr(host, callback, options, verify):
        """Register a SignalR callback and start listening."""
        from signalrcore.hub_connection_builder import HubConnectionBuilder
        if not callback:
            raise Exception("A callback must be specified to register for the SignalR events.")
        options.update({'verify_ssl':verify})
        server_url = _assemble_url(host, _assemble_path(Services.EVENT, 'signalr'))
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
        hub_connection.on_open(lambda: print("connection opened and handshake received ready to send messages"))
        hub_connection.on_close(lambda: print("connection closed"))
        hub_connection.start()

    @staticmethod
    def register_signalr_username(conn, callback, username, password):
        """Wrapper to register a SignalR callback using username/password authentication.
        
        Arguments:
        conn -- PySafeguardConnection instance object
        callback -- Callback function to handle messages that come back
        username -- Username for authentication
        password -- Password for authentication
        """
        def _token_factory_username():
            conn.connect_password(username, password)
            return conn.UserToken
        options = {"access_token_factory": _token_factory_username}
        PySafeguardConnection.__register_signalr(conn.host, callback, options, bool(conn.req_globals.get('verify',True)))

    @staticmethod
    def register_signalr_certificate(conn, callback, certfile, keyfile):
        """Wrapper to register a SignalR callback using certificate authentication.
        
        Arguments:
        conn -- PySafeguardConnection instance object
        callback -- Callback function to handle messages that come back
        certfile -- Path to the user certificate in pem format.
        keyfile -- Path to the user certificate's key in key format.
        """
        def _token_factory_certificate():
            conn.connect_certificate(certfile, keyfile, provider="certificate")
            return conn.UserToken
        options = options={"access_token_factory": _token_factory_certificate}
        PySafeguardConnection.__register_signalr(conn.host, callback, options, bool(conn.req_globals.get('verify',True)))
    
