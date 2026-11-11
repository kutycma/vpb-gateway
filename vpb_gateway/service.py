import asyncio
from contextlib import asynccontextmanager
from .db import DB
from .state import State
from .vpbank import VPBank
from .alerts import Alerts
from .fetcher import Fetcher
from .fcm import Listener
from .webhook import Outbox

class Service:
    def __init__(self,config):
        self.config=config; self.db=DB(config['storage']['db_path']); self.state=State(config['storage']['state_path'])
        self.db.configure_crypto(self.state)
        self.db.webhook_allow_insecure=config['routing'].get('webhook_allow_insecure', [])
        self.bank=VPBank(config['vpbank'],self.state); self.alerts=Alerts(config['telegram'])
        self.fetcher=Fetcher(self.bank,self.db,config,self.alerts)
        self.fcm=Listener(self.state,self.fetcher,self.db,self.alerts,config)
        self.outbox=Outbox(self.db,self.alerts)
    @asynccontextmanager
    async def lifespan(self,app):
        # Serve setup/status before registration without sending unauthenticated
        # background requests to the bank. Restart after register loads state.
        tasks=[asyncio.create_task(self.outbox.run())]
        if self.state.data.get('auth_key'):
            tasks.extend(asyncio.create_task(c) for c in (self.fetcher.run(),self.fetcher.poll(self.fcm),self.fcm.run()))
            self.fetcher.trigger('startup')
        try: yield
        finally:
            for t in tasks: t.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)
            await self.close()
    async def close(self):
        await self.bank.client.aclose(); await self.outbox.client.aclose(); self.db.conn.close()
