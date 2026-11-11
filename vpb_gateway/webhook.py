import asyncio
import hashlib
import hmac
import time
import httpx
from .db import now
from .security import webhook_url

RETRIES = [10,30,120,600,1800,3600,7200,14400,28800]
def signature(secret,timestamp,body):
    return 'sha256='+hmac.new(secret.encode(),str(timestamp).encode()+b'.'+body,hashlib.sha256).hexdigest()

class Outbox:
    def __init__(self,db,alerts,client=None):
        self.db,self.alerts=db,alerts
        self.client=client or httpx.AsyncClient(timeout=10,follow_redirects=False)
        self.lock=asyncio.Lock()
    async def deliver(self,d):
        routes=await asyncio.to_thread(self.db.rows,'SELECT * FROM routes WHERE name=?',(d['route'],))
        code=None
        error=None
        try:
            if not routes: raise ValueError('Route removed')
            r=routes[0]
            target = await asyncio.to_thread(webhook_url, r['webhook_url'], getattr(self.db, 'webhook_allow_insecure', ()), True)
            body=d['payload'].encode(); stamp=str(int(time.time()))
            async with self.client.stream('POST',target,content=body,extensions={'sni_hostname':httpx.URL(r['webhook_url']).host},headers={'Host':httpx.URL(r['webhook_url']).netloc.decode(),'Content-Type':'application/json','User-Agent':'vpb-gateway/0.1.0','X-VPG-Event-Id':d['event_id'],'X-VPG-Timestamp':stamp,'X-VPG-Signature':signature(r['secret'],stamp,body)}) as response:
                code=response.status_code
            if not 200<=code<300: error='HTTP failure'
        except (httpx.HTTPError,ValueError): error='Delivery unavailable'
        attempts=d['attempts']+1
        status='success' if error is None else ('failed' if attempts>len(RETRIES) else 'pending')
        due=time.time()+RETRIES[min(attempts-1,len(RETRIES)-1)]
        await asyncio.to_thread(self.db.execute,'UPDATE deliveries SET status=?,attempts=?,next_attempt_at=?,last_status_code=?,last_error=?,updated_at=? WHERE id=?',(status,attempts,due,code,error,now(),d['id']))
        if status=='failed': await self.alerts.send('Webhook delivery permanently failed')
    async def tick(self):
        async with self.lock:
            rows=await asyncio.to_thread(self.db.rows,"SELECT * FROM deliveries WHERE status='pending' AND next_attempt_at<=? LIMIT 4",(time.time(),))
            await asyncio.gather(*(self.deliver(d) for d in rows))
    async def run(self):
        while True:
            await self.tick()
            await asyncio.sleep(1)
