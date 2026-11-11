import httpx
import respx
from tests.test_gateway import service,RAW
from vpb_gateway.ingest import ingest
from vpb_gateway.api import app_for
from vpb_gateway.alerts import transaction_message

ADMIN={'Authorization':'Bearer admin'}

async def test_admin_transactions_csv_summary(service):
    s=service
    ingest(s.db,{'a':[RAW,RAW.replace('DH123abc','khong ma'),RAW.replace('10000VND','-5000VND')]},s.config)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_for(s)),base_url='http://api') as client:
        assert (await client.get('/admin/transactions')).status_code==401
        assert (await client.get('/admin/transactions',headers={'Authorization':'Bearer unmatched'})).status_code==403
        page=(await client.get('/admin/transactions',headers=ADMIN)).json()
        assert [t['id'] for t in page['items']]==[3,2,1] and page['items'][2]['codes']==['DH123']
        page=(await client.get('/admin/transactions?status=unmatched',headers=ADMIN)).json()
        assert [t['content'] for t in page['items']]==['khong ma']
        page=(await client.get('/admin/transactions?q=123&limit=1',headers=ADMIN)).json()
        assert len(page['items'])==1 and page['next_before_id']==page['items'][0]['id']
        page=(await client.get('/admin/transactions?before_id=2',headers=ADMIN)).json()
        assert [t['id'] for t in page['items']]==[1]
        r=await client.get('/admin/transactions.csv?route=shop&status=matched',headers=ADMIN)
        assert r.status_code==200 and r.headers['content-type'].startswith('text/csv')
        lines=r.text.lstrip('﻿').splitlines()
        assert lines[0].startswith('id,thoi_gian_ngan_hang') and len(lines)==2 and ',DH123abc,' in lines[1]
        summary=(await client.get('/admin/summary',headers=ADMIN)).json()
        assert summary['open_unmatched']==1 and summary['routes']==['shop']
        assert {x['status']:x['count'] for x in summary['by_status']}=={'matched':1,'unmatched':1,'outgoing':1}
        html=await client.get('/admin/ui')
        from pathlib import Path
        import vpb_gateway.api
        if (Path(vpb_gateway.api.__file__).parent/'static'/'admin.html').is_file():
            assert html.status_code==200 and 'VPBank Gateway' in html.text and 'admin/transactions.csv' in html.text
        else:
            assert html.status_code==404

async def test_admin_token_manages_unmatched(service):
    s=service
    ingest(s.db,{'a':[RAW.replace('DH123abc','khong ma'),RAW.replace('DH123abc','khac')]},s.config)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_for(s)),base_url='http://api') as client:
        assert (await client.post('/v1/unmatched/1/assign',headers=ADMIN,json={'route':'shop','order_id':'55'})).status_code==200
        assert (await client.post('/v1/unmatched/2/ignore',headers=ADMIN,json={'note':'test'})).status_code==200
        assert (await client.get('/v1/unmatched',headers={'Authorization':'Bearer '+s.keys['api_key']})).status_code==403
    rows=s.db.rows('SELECT status,code,note FROM transactions ORDER BY id')
    assert rows[0]['status']=='matched' and rows[0]['code']=='DH55' and rows[1]['status']=='ignored' and rows[1]['note']=='test'

async def test_transaction_notifications(service):
    s=service
    s.alerts.config.update(bot_token='t',chat_id='c')
    with respx.mock as mock:
        mock.get('https://bank.test/cb/odata/ns/authenticationservice/GetNonSecureNotificationShare').mock(return_value=httpx.Response(200,json={'d':{'Status':'true','Message':'{"a":["%s","%s"]}'%(RAW,RAW.replace('DH123abc','khong ma'))}}))
        tele=mock.post('https://api.telegram.org/bott/sendMessage').mock(return_value=httpx.Response(200,json={'ok':True}))
        assert await s.fetcher.fetch()==2
        texts=[httpx.Request(c.request.method,c.request.url,content=c.request.content).read().decode() for c in tele.calls]
        assert any('+10.000 đ | DH123abc' in t and 'DH123 → shop' in t for t in texts)
        assert any('khong ma' in t and 'Chưa khớp' in t for t in texts)
        # Nothing new → no further notifications.
        n=len(tele.calls); await s.fetcher.fetch(); assert len(tele.calls)==n
    s.config['alerts']['notify_transactions']=False
    with respx.mock as mock:
        mock.get('https://bank.test/cb/odata/ns/authenticationservice/GetNonSecureNotificationShare').mock(return_value=httpx.Response(200,json={'d':{'Status':'true','Message':'{"a":["%s"]}'%RAW.replace('19:46','19:47')}}))
        tele=mock.post('https://api.telegram.org/bott/sendMessage').mock(return_value=httpx.Response(200,json={'ok':True}))
        assert await s.fetcher.fetch()==1
        assert all('Transaction' in httpx.Request(c.request.method,c.request.url,content=c.request.content).read().decode() for c in tele.calls)

def test_transaction_message():
    m=transaction_message(dict(amount=1234567,direction='in',status='matched',code='ZD1',route='shop',content='Zd1',bank_time='2026-11-09T21:30:00+07:00',account='0123456789'))
    assert m.startswith('+1.234.567 đ | Zd1\n✅ ZD1 → shop\n2026-11-09 21:30')
    assert 'Khớp nhiều tuyến' in transaction_message(dict(amount=1,direction='in',status='unmatched',reason='ambiguous'))

async def test_admin_ui_missing_is_404(service, monkeypatch):
    from pathlib import Path
    original = Path.is_file
    monkeypatch.setattr(Path, 'is_file', lambda p: False if p.name == 'admin.html' else original(p))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_for(service)),base_url='http://api') as client:
        assert (await client.get('/admin/ui')).status_code == 404
        assert (await client.get('/admin/')).status_code == 404
