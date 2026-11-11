import ipaddress
PUBLIC_TEST_IP = str(ipaddress.IPv4Address(0x08080808))
import asyncio
import copy
import json
import httpx
import pytest
import respx
from vpb_gateway.config import DEFAULTS
from vpb_gateway.db import DB
from vpb_gateway.parser import parse_line
from vpb_gateway.router import match,validate_route,token_hash
from vpb_gateway.ingest import ingest
from vpb_gateway.api import create_route,app_for
from vpb_gateway.service import Service
from vpb_gateway.webhook import signature,RETRIES
from vpb_gateway.vpbank import WafBlocked,AuthRejected,TransientError

RAW='VPB:09/11/2026 19:46|XXXXXX6789|10000VND|00000VND|DH123abc'
@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setattr("vpb_gateway.security.socket.getaddrinfo", lambda *a, **k: [(2,1,6,"",(PUBLIC_TEST_IP,443))])
    c=copy.deepcopy(DEFAULTS)
    c['storage']={'db_path':str(tmp_path/'gateway.db'),'state_path':str(tmp_path/'state.json')}
    c['vpbank']['base_url']='https://bank.test'
    c['fetch'].update(bootstrap='process',min_fetch_interval_seconds=0,followup_delays=[0,0])
    s=Service(c)
    s.keys=create_route(s.db,dict(name='shop',prefix='DH',webhook_url='https://hook.test/pay'))
    c['auth']={'admin_token_hash':token_hash('admin'),'unmatched_token_hash':token_hash('unmatched')}
    yield s
    s.db.conn.close()

def test_parser():
    t=parse_line(RAW,'a'); assert t.amount==10000 and t.content=='DH123abc' and t.bank_time.endswith('+07:00')
    assert parse_line(RAW.replace('10000VND','-10,000VND'),'a').direction=='out'
    assert parse_line(RAW+'|x','a').content.endswith('|x')
    with pytest.raises(ValueError): parse_line('bad','a')

@pytest.mark.parametrize('content',['DH123abc','DH 123','dh-123','DH_123','DH.123'])
def test_router(service,content):
    assert match(content,service.db.rows('SELECT * FROM routes'))['order_id']=='123'
def test_conflict_ambiguous(service):
    with pytest.raises(ValueError): create_route(service.db,dict(name='bad',prefix='DHX',webhook_url='https://x.example'))
    create_route(service.db,dict(name='other',prefix='AB',webhook_url='https://x.example'))
    assert match('DH123 AB456',service.db.rows('SELECT * FROM routes'))['reason']=='ambiguous'
    assert match('ADH123',service.db.rows('SELECT * FROM routes'))['reason']=='no_match'

def test_multiset(service):
    s=service
    assert ingest(s.db,{'a':[RAW,RAW]},s.config)==2
    assert ingest(s.db,{'a':[RAW]},s.config)==0
    assert ingest(s.db,{'a':[RAW]*3},s.config)==1
    assert len(s.db.rows('SELECT * FROM deliveries'))==3
def test_bootstrap(service):
    s=service;s.config['fetch']['bootstrap']='ignore'
    assert ingest(s.db,{'a':[RAW]},s.config)==1
    assert s.db.rows('SELECT status FROM transactions')[0]['status']=='bootstrap'
    assert not s.db.rows('SELECT * FROM deliveries')
def test_empty_bootstrap(service):
    s=service;s.config['fetch']['bootstrap']='ignore'
    ingest(s.db,{},s.config);ingest(s.db,{'a':[RAW]},s.config)
    assert s.db.rows('SELECT status FROM transactions')[0]['status']=='matched'
def test_parse_outgoing(service):
    s=service;ingest(s.db,{'a':['bad',RAW.replace('10000VND','-10000VND')]},s.config)
    assert {r['status'] for r in s.db.rows('SELECT status FROM transactions')}=={'parse_error','outgoing'}
def test_hmac():
    import hmac,hashlib
    assert signature('secret','123',b'{}')=='sha256='+hmac.new(b'secret',b'123.{}',hashlib.sha256).hexdigest()
    assert RETRIES==[10,30,120,600,1800,3600,7200,14400,28800]

async def test_api_scope_assign(service):
    s=service
    ingest(s.db,{'a':[RAW,RAW.replace('DH123abc','unknown')]},s.config)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_for(s)),base_url='http://api') as client:
        assert (await client.get('/v1/transactions')).status_code==401
        assert (await client.get('/v1/transactions',headers={'Authorization':'Bearer unmatched'})).status_code==403
        own={'Authorization':'Bearer '+s.keys['api_key']}
        page=(await client.get('/v1/transactions',headers=own)).json()
        assert len(page['items'])==1
        assert page['next_after_id']==page['items'][-1]['id']
        assert (await client.get('/v1/transactions/2',headers=own)).status_code==404
        h={'Authorization':'Bearer unmatched'}
        body={'route':'shop','order_id':'789'}
        assert (await client.post('/v1/unmatched/2/assign',headers=h,json=body)).status_code==200
        assert (await client.post('/v1/unmatched/2/assign',headers=h,json=body)).status_code==200
        assert len(s.db.rows('SELECT * FROM deliveries'))==2
        assert (await client.post('/v1/unmatched/2/ignore',headers=h,json={})).status_code==409

async def test_trigger_delivery_retry(service):
    s=service
    with respx.mock as mock:
        mock.get('https://bank.test/cb/odata/ns/authenticationservice/GetNonSecureNotificationShare').mock(return_value=httpx.Response(200,json={'d':{'Status':'true','Message':json.dumps({'a':[RAW]})}}))
        calls=[]
        def hook(request):
            assert request.headers['X-VPG-Signature']==signature(s.keys['secret'],request.headers['X-VPG-Timestamp'],request.content)
            calls.append(json.loads(request.content)); return httpx.Response(500 if len(calls)==1 else 204)
        mock.post(f'https://{PUBLIC_TEST_IP}/pay').mock(side_effect=hook)
        task=asyncio.create_task(s.fetcher.run());s.fcm.message({'data':{'type':'BALANCE_CHANGING'}})
        for _ in range(100):
            if s.fetcher.last_fetch_ok_at: break
            await asyncio.sleep(.01)
        task.cancel();await asyncio.gather(task,return_exceptions=True)
        await s.outbox.tick()
        assert s.db.rows('SELECT status FROM deliveries')[0]['status']=='pending'
        s.db.execute('UPDATE deliveries SET next_attempt_at=0')
        await s.outbox.tick()
        assert s.db.rows('SELECT status FROM deliveries')[0]['status']=='success'
        assert calls[0]['event_id']==calls[1]['event_id']

@pytest.mark.parametrize('response,error',[(httpx.Response(200,text='<html>Incapsula</html>'),WafBlocked),(httpx.Response(403,json={}),AuthRejected),(httpx.Response(503),TransientError)])
async def test_bank_errors(service,response,error):
    with respx.mock as mock:
        mock.get('https://bank.test/cb/odata/ns/authenticationservice/GetNonSecureNotificationShare').mock(return_value=response)
        with pytest.raises(error): await service.bank.fetch_history()


def test_multi_patterns_migration(service):
    s=service
    original=s.db.rows('SELECT * FROM routes')[0]
    s.db.conn.close()
    s.db=DB(s.config['storage']['db_path'])
    s.db.configure_crypto(s.state)
    restored=s.db.rows('SELECT * FROM routes')[0]
    assert restored['secret']==original['secret'] and restored['api_key_hash']==original['api_key_hash']
    create_route(s.db,dict(name='multi',patterns=[dict(prefix='ZD',id_pattern='[A-HJ-NP-Z2-9]{8}'),dict(prefix='SHOP',id_pattern='[0-9A-F]{32}|[0-9]{1,12}'),dict(prefix='ZICNAP',id_pattern='[0-9A-F]{32}')],webhook_url='https://hook.test'))
    routes=s.db.rows('SELECT * FROM routes')
    for text,order in [('Zdp5qkvmaj','P5QKVMAJ'),('SHOP'+'A'*32,'A'*32),('SHOP123','123'),('ZICNAP'+'B'*32,'B'*32)]:
        assert match(text,routes)['order_id']==order
    with pytest.raises(ValueError): create_route(s.db,dict(name='conflict',prefix='ZICNAPX',webhook_url='https://x.example'))

async def test_forward_and_pull(service):
    s=service;s.config['routing']['forward_unmatched_to']='shop'
    create_route(s.db,dict(name='other',prefix='AB',webhook_url='https://x.example'))
    ingest(s.db,{'a':[RAW,RAW.replace('DH123abc','unknown'),RAW.replace('DH123abc','DH123 AB456')]},s.config)
    ingest(s.db,{'sim':[RAW]},s.config,simulated=True)
    ds=s.db.rows('SELECT * FROM deliveries')
    assert len(ds)==3
    ps=[json.loads(d['payload']) for d in ds]
    assert [p['type'] for p in ps]==['transaction.matched','transaction.unmatched','transaction.matched']
    assert [p['simulated'] for p in ps]==[False,False,True]
    assert ps[1]['transaction']['code'] is None and ps[1]['transaction']['codes']==[]
    assert ps[0]['transaction']['uid'] and ps[0]['transaction']['direction']=='in'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_for(s)),base_url='http://api') as client:
        headers={'Authorization':'Bearer '+s.keys['api_key']}
        page=(await client.get('/v1/transactions?limit=1',headers=headers)).json()
        assert len(page['items'])==1 and page['next_after_id']==1
        page=(await client.get('/v1/transactions?after_id=1',headers=headers)).json()
        assert [t['type'] for t in page['items']]==['transaction.unmatched'] and page['next_after_id']==2
        assert (await client.get('/v1/transactions?after_id=2',headers=headers)).json()==dict(items=[],next_after_id=2)
        admin={'Authorization':'Bearer admin'}
        await client.post('/admin/routes/shop/test',headers=admin)
        ping=json.loads(s.db.rows('SELECT payload FROM deliveries ORDER BY id DESC')[0]['payload'])
        assert ping['simulated'] is False and 'transaction' not in ping


def test_v1_migration_preserves_credentials(tmp_path):
    import sqlite3
    from vpb_gateway.db import SCHEMA
    path=tmp_path/'old.db'
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
        conn.execute("INSERT INTO routes(name,prefix,webhook_url,secret,id_pattern,api_key_hash) VALUES('test','DH','https://test','old-secret','[0-9]{1,20}','old-key')")
    db=DB(path)
    route=db.rows('SELECT * FROM routes')[0]
    assert route['secret']=='old-secret' and route['api_key_hash']=='old-key'
    assert match('DH123',[route])['order_id']=='123'
    assert db.rows("SELECT value FROM meta WHERE key='schema_version'")[0]['value']=='2'
    db.conn.close()


def test_conflict_within_pattern_list(service):
    with pytest.raises(ValueError):
        create_route(service.db,dict(name='invalid',webhook_url='https://hook.test',patterns=[
            dict(prefix='ZX',id_pattern='[0-9]+'),
            dict(prefix='ZXY',id_pattern='[0-9]+')]))
    assert not service.db.rows("SELECT * FROM routes WHERE name='invalid'")

async def test_forwarded_webhook_delivery(service):
    s=service
    s.config['routing']['forward_unmatched_to']='shop'
    ingest(s.db,{'a':[RAW.replace('DH123abc','unknown')]},s.config)
    with respx.mock as mock:
        def hook(request):
            payload=json.loads(request.content)
            assert payload['type']=='transaction.unmatched'
            assert payload['route']=='shop'
            assert payload['simulated'] is False
            assert payload['transaction']['direction']=='in'
            assert payload['transaction']['uid']
            assert request.headers['X-VPG-Event-Id']==payload['event_id']
            assert request.headers['X-VPG-Signature']==signature(s.keys['secret'],request.headers['X-VPG-Timestamp'],request.content)
            return httpx.Response(204)
        endpoint=mock.post(f'https://{PUBLIC_TEST_IP}/pay').mock(side_effect=hook)
        await s.outbox.tick()
        assert endpoint.call_count==1
        assert s.db.rows('SELECT status FROM deliveries')[0]['status']=='success'
