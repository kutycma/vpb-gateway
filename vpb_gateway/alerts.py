import logging
import time
import httpx

class Alerts:
    def __init__(self, config):
        self.config, self.sent = config, {}
    def configured(self):
        return bool(self.config.get('bot_token') and self.config.get('chat_id'))
    async def send(self, message):
        # Operational alerts: identical text is suppressed for 30 minutes.
        if time.time()-self.sent.get(message,0)<1800: return
        self.sent[message]=time.time()
        logging.warning('%s',message)
        await self._telegram(message)
    async def notify(self, message):
        # Per-transaction notifications: never deduplicated, Telegram only.
        if self.configured(): await self._telegram(message)
    async def _telegram(self, message):
        if not self.configured(): return
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post('https://api.telegram.org/bot'+self.config['bot_token']+'/sendMessage',json={'chat_id':self.config['chat_id'],'text':message})
        except httpx.HTTPError: logging.warning('Telegram alert failed')

def transaction_message(tx):
    amount=f"{tx.get('amount') or 0:,}".replace(',','.')
    sign='+' if tx.get('direction')=='in' else '-'
    status=tx.get('status')
    if status=='matched':
        where=f"✅ {tx.get('code')} → {tx.get('route')}"
    elif status=='unmatched':
        where='⚠️ Chưa khớp mã' if tx.get('reason')!='ambiguous' else '⚠️ Khớp nhiều tuyến'
    else:
        where=f'ℹ️ {status}'
    when=(tx.get('bank_time') or '')[:16].replace('T',' ')
    return f"{sign}{amount} đ | {tx.get('content') or ''}\n{where}\n{when} | TK {tx.get('account') or ''}"
