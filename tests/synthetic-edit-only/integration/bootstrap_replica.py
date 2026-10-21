"""Only run after an official mongod is listening on loopback port27191."""
import time
from pymongo import MongoClient
c=MongoClient('mongodb://127.0.0.1:27191/?directConnection=true',serverSelectionTimeoutMS=3000)
c.admin.command('ping')
try:c.admin.command('replSetInitiate',{'_id':'synthetic_rs','members':[{'_id':0,'host':'127.0.0.1:27191'}]})
except Exception as e:
    if getattr(e,'code',None)!=23:raise
for _ in range(100):
    if c.admin.command('hello').get('isWritablePrimary'):break
    time.sleep(.1)
else:raise RuntimeError('Replica set failed to elect primary')
print('synthetic_rs ready; loopback only')
