import ipaddress
METADATA_TEST_IP = str(ipaddress.IPv4Address(0xA9FEA9FE))
import time, socket, sqlite3
import pytest, httpx
from tests.test_gateway import service
from vpb_gateway.security import webhook_url, safe_pattern, csv_cell
from vpb_gateway.api import app_for

@pytest.mark.parametrize('url',['http://example.com','https://127.0.0.1','https://[::1]','https://localhost','https://metadata.google.internal','https://user:pass' + '@' + 'example.com'])
def test_webhook_reject(url):
    with pytest.raises(ValueError): webhook_url(url)

def test_dns_and_exception(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(2,1,6,'',(METADATA_TEST_IP,443))])
    with pytest.raises(ValueError): webhook_url('https://example.com',resolve=True)
    webhook_url('http://127.0.0.1:8091/hook',['http://127.0.0.1:8091/hook'],True)
    with pytest.raises(ValueError): webhook_url('http://127.0.0.1:8091/other',['http://127.0.0.1:8091/hook'])

@pytest.mark.parametrize('pattern',['(a+)+','[0-9]+','a{1,100}a{1,100}','a{1,999}','(a|aa){1,20}','a'*65])
def test_regex_reject_fast(pattern):
    start=time.monotonic()
    with pytest.raises(ValueError): safe_pattern(pattern)
    assert time.monotonic()-start<0.1

def test_adversarial_regex():
    import re
    safe_pattern('[A-Z]{1,128}')
    start=time.monotonic()
    assert re.search('[A-Z]{1,128}!', 'A'*100000+'x') is None
    assert time.monotonic()-start<1

@pytest.mark.parametrize('text',['=SUM(A1)','+1','-1','@x','\tt','\rx'])
def test_csv(text): assert csv_cell(text)=="'"+text

async def test_body_limit(service):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_for(service)),base_url='http://api') as c:
        assert (await c.post('/admin/routes',content=b'x'*65537)).status_code==413
        async def chunks():
            for _ in range(17): yield b'x'*4096
        assert (await c.post('/admin/routes',content=chunks())).status_code==413

def test_encryption_retention(service):
    db=service.db
    assert db.conn.execute('SELECT secret FROM routes').fetchone()[0].startswith('aesgcm:')
    assert db.rows('SELECT * FROM routes')[0]['secret']==service.keys['secret']
    for status in ('success','pending','failed'):
        db.execute('INSERT INTO deliveries(status,updated_at) VALUES(?,?)',(status,'2020-01-01'))
    db.prune()
    assert {r['status'] for r in db.rows('SELECT status FROM deliveries')}=={'pending','failed'}

async def test_route_policy_api(service):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_for(service)),base_url='http://api') as c:
        headers={'Authorization':'Bearer admin'}
        assert (await c.post('/admin/routes',headers=headers,json={'name':'bad','prefix':'AB','webhook_url':f'http://{METADATA_TEST_IP}/x'})).status_code==400
        assert (await c.patch('/admin/routes/shop',headers=headers,json={'webhook_url':'https://127.0.0.1'})).status_code==400
        assert service.db.rows('SELECT * FROM routes')[0]['webhook_url']=='https://hook.test/pay'
        assert (await c.post('/admin/routes/shop/rotate-secret',headers=headers)).status_code==200
        assert service.db.conn.execute('SELECT secret FROM routes').fetchone()[0].startswith('aesgcm:')
