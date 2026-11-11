import asyncio
import pytest
from tests.test_gateway import service,RAW

async def test_dirty_single_flight(service):
    s=service;entered=asyncio.Event();release=asyncio.Event();calls=0;active=0
    async def history():
        nonlocal calls,active
        calls+=1;active+=1
        assert active==1
        if calls==1:
            entered.set();await release.wait()
        active-=1
        return {}
    s.bank.fetch_history=history
    task=asyncio.create_task(s.fetcher.run());s.fetcher.trigger('startup')
    await asyncio.wait_for(entered.wait(),1)
    for _ in range(10): s.fetcher.trigger('manual')
    release.set()
    for _ in range(100):
        if calls==2: break
        await asyncio.sleep(.01)
    task.cancel();await asyncio.gather(task,return_exceptions=True)
    assert calls==2

async def test_followups(service):
    s=service;calls=0
    async def history():
        nonlocal calls
        calls+=1
        return {'a':[RAW]} if calls==3 else {}
    s.bank.fetch_history=history
    task=asyncio.create_task(s.fetcher.run());s.fetcher.trigger('fcm')
    for _ in range(100):
        if s.db.rows('SELECT * FROM transactions'): break
        await asyncio.sleep(.01)
    task.cancel();await asyncio.gather(task,return_exceptions=True)
    assert calls==3 and len(s.db.rows('SELECT * FROM deliveries'))==1

def test_atomic_outbox_and_restart(service):
    from vpb_gateway.db import DB
    from vpb_gateway.ingest import ingest
    s=service
    ingest(s.db,{'a':[RAW]},s.config)
    db=DB(s.config['storage']['db_path'])
    try:
        assert db.rows('SELECT status FROM deliveries')[0]['status']=='pending'
        assert ingest(db,{'a':[RAW]},s.config)==0
    finally: db.conn.close()

def test_rollback(service,monkeypatch):
    import vpb_gateway.ingest as module
    def fail(*args): raise RuntimeError('Injected write failure')
    monkeypatch.setattr(module,'queue',fail)
    with pytest.raises(RuntimeError): module.ingest(service.db,{'a':[RAW]},service.config)
    assert not service.db.rows('SELECT * FROM transactions')
    assert not service.db.rows('SELECT * FROM seen_lines')
