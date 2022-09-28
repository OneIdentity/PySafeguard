from pysafeguard import *

conn = PySafeguardConnection('myappliance', 'ssl/pathtoca.pem')
ADprovider = conn.get_provider_id('ad.sample.corp')
conn.connect_password('username', 'password', ADprovider)
me = conn.invoke(HttpMethods.GET, Services.CORE, 'Me').json()
print('My DisplayName is %s' % me['DisplayName'])
