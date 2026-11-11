import asyncio
import time
from .db import now
from .ingest import ingest
from .alerts import transaction_message
from .vpbank import AuthRejected, TransientError, WafBlocked

class Fetcher:
    def __init__(self,bank,db,config,alerts):
        self.bank,self.db,self.config,self.alerts=bank,db,config,alerts
        self.event=asyncio.Event(); self.reasons=set(); self.last=0
        self.last_fetch_ok_at=None; self.last_fetch_error=None; self.failures=0; self.auth_rejected=False
    def trigger(self,reason):
        self.reasons.add(reason); self.event.set()
    async def fetch(self):
        await asyncio.sleep(max(0,self.config['fetch']['min_fetch_interval_seconds']-(time.monotonic()-self.last)))
        self.last=time.monotonic()
        try:
            history=await self.bank.fetch_history()
            previous=(await asyncio.to_thread(self.db.rows,'SELECT coalesce(max(id),0) AS id FROM transactions'))[0]['id']
            added=await asyncio.to_thread(ingest,self.db,history,self.config)
            self.last_fetch_ok_at=now(); self.last_fetch_error=None; self.failures=0; self.auth_rejected=False
            await asyncio.to_thread(self.db.event,'fetch',f'new={added}')
            for status in ('parse_error','unmatched'):
                if status=='unmatched' and not self.config['alerts']['alert_on_unmatched']: continue
                if added and await asyncio.to_thread(self.db.rows,'SELECT 1 FROM transactions WHERE status=? AND id>? LIMIT 1',(status,previous)):
                    await self.alerts.send('Transaction '+status)
            if added and self.config['alerts'].get('notify_transactions',True) and self.alerts.configured():
                rows=await asyncio.to_thread(self.db.rows,"SELECT * FROM transactions WHERE id>? AND simulated=0 AND status IN ('matched','unmatched') ORDER BY id",(previous,))
                for tx in rows: await self.alerts.notify(transaction_message(tx))
            return added
        except (AuthRejected,TransientError,WafBlocked) as e:
            self.failures+=1; self.last_fetch_error=type(e).__name__; self.auth_rejected=isinstance(e,AuthRejected)
            if self.auth_rejected or isinstance(e,WafBlocked) or self.failures>=self.config['alerts']['alert_after_failures']: await self.alerts.send(self.last_fetch_error)
            return None
    async def run(self):
        while True:
            await self.event.wait(); self.event.clear(); reasons=self.reasons; self.reasons=set()
            new=await self.fetch()
            if new is None:
                await asyncio.sleep(600 if self.auth_rejected else [5,15,60,300][min(self.failures-1,3)])
                self.trigger('retry')
            elif new==0 and 'fcm' in reasons:
                previous_delay=0
                for delay in self.config['fetch']['followup_delays']:
                    await asyncio.sleep(max(0,delay-previous_delay)); previous_delay=delay
                    result=await self.fetch()
                    if result is None:
                        self.trigger('retry'); break
                    if result: break
    async def poll(self,fcm=None):
        while True:
            seconds=self.config['fetch']['safety_poll_seconds']
            if fcm is not None and not fcm.connected:
                seconds=self.config['fetch'].get('poll_when_fcm_down_seconds',60)
            await asyncio.sleep(min(seconds,5) if seconds else 5)
            if seconds and time.monotonic()-self.last>=seconds:
                self.trigger('fcm_down_poll' if fcm is not None and not fcm.connected else 'poll')
