import json
import httpx

class WafBlocked(Exception): pass
class AuthRejected(Exception): pass
class TransientError(Exception): pass

class VPBank:
    def __init__(self, config, state, client=None):
        self.config, self.state = config, state
        self.client = client or httpx.AsyncClient(base_url=config['base_url'], timeout=15, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0' + '.0.0 Safari/537.36',
            'Origin': 'https://neo.vpbank.com.vn', 'Referer': 'https://neo.vpbank.com.vn/notification.html',
            'Accept-Language': 'vi-VN,vi;q=0.9', 'Accept': 'application/json', 'Content-Type': 'application/json'})

    async def request(self, endpoint, **kwargs):
        try:
            r = await self.client.get('/cb/odata/ns/authenticationservice/' + endpoint, **kwargs)
        except httpx.HTTPError:
            raise TransientError('Network failure') from None
        if r.status_code >= 500:
            raise TransientError('Bank server failure')
        if 'incapsula' in r.text.lower() or r.text.lstrip().startswith('<'):
            raise WafBlocked('WAF response')
        if r.status_code in (401,403):
            raise AuthRejected('Authentication rejected')
        try:
            return r.json()['d']
        except (ValueError, KeyError, TypeError):
            raise WafBlocked('Invalid JSON response') from None

    async def validate(self, key, pin):
        d = await self.request('ValidationNonSecureNotificationShare', params={'KeyShare': "'"+key+"'", 'PinShare': "'"+pin+"'"})
        if str(d.get('Status')) != '2': raise AuthRejected('KEY/PIN rejected')
        return True

    async def register(self, key, pin, fcm_token):
        d = await self.request('ValidationNonSecureNotificationShare', params={'KeyShare': "'"+key+"'", 'PinShare': "'"+pin+"'"}, headers={'TokenFB': fcm_token})
        if str(d.get('Status')) != '1' or not d.get('Jwt'): raise AuthRejected('Registration rejected')
        return d['Jwt']

    async def fetch_history(self):
        s = self.state.data
        d = await self.request('GetNonSecureNotificationShare', headers={'AuthKey': s.get('auth_key',''), 'KeyShare': s.get('key',''), 'PinShare': s.get('pin',''), 'AccountNumber': self.config.get('account_number','all')})
        if str(d.get('Status')).lower() != 'true': raise AuthRejected('History rejected')
        try:
            data = json.loads(d['Message'])
            if not isinstance(data, dict) or any(not isinstance(v,list) or any(not isinstance(x,str) for x in v) for v in data.values()): raise ValueError()
            return data
        except (ValueError,KeyError,TypeError): raise TransientError('Malformed history') from None
