import json
from pysafeguard import *
conn = PySafeguardConnection('10.5.32.56')
req = conn.invoke(HttpMethods.GET,Services.APPLIANCE,'SystemTime')
print(json.dumps(req.json(),indent=2,sort_keys=True))
conn.connect_password('Admin','Admin123')
req = conn.invoke(HttpMethods.GET,Services.CORE,'Me')
print(json.dumps(req.json(),indent=2,sort_keys=True))