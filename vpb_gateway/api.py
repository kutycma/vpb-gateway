import asyncio
import csv
import io
import json
import secrets
import time
import uuid
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse, Response
from fastapi.exceptions import RequestValidationError
from .router import token_hash, validate_route
from .ingest import queue, transaction_payload
from .db import now
from .security import webhook_url, csv_cell, BodyLimit

def create_route(db, values):
    with db.lock:
        return _create_route(db,values)

def _create_route(db, values):
    values=dict(values)
    if any(not isinstance(values.get(k),str) or not values[k] for k in ('name','webhook_url')):
        raise ValueError('Missing route fields')
    key=secrets.token_urlsafe(32); secret=secrets.token_urlsafe(32)
    values.setdefault('secret',secret); values.setdefault('enabled',1)
    values['api_key_hash']=token_hash(key)
    validate_route(values,db.rows('SELECT * FROM routes'))
    webhook_url(values['webhook_url'], getattr(db, 'webhook_allow_insecure', ()))
    keys=('name','prefix','webhook_url','secret','id_pattern','enabled','api_key_hash','patterns_json')
    db.execute(f"INSERT INTO routes({','.join(keys)}) VALUES(?,?,?,?,?,?,?,?)",tuple(db.encrypt_secret(values['name'], values[k]) if k=='secret' else values[k] for k in keys))
    return {'name':values['name'],'secret':values['secret'],'api_key':key}

def app_for(service, lifespan=None):
    app=FastAPI(lifespan=lifespan)
    app.add_middleware(BodyLimit)
    db=service.db
    @app.exception_handler(HTTPException)
    async def http_error(request,e):
        return JSONResponse({'error':{'code':str(e.status_code),'message':str(e.detail)}},status_code=e.status_code)
    @app.exception_handler(RequestValidationError)
    async def validation_error(request,e):
        return JSONResponse({'error':{'code':'422','message':'Invalid request'}},status_code=422)
    @app.exception_handler(ValueError)
    async def value_error(request,e):
        return JSONResponse({'error':{'code':'invalid','message':'Invalid or conflicting values'}},status_code=400)
    @app.exception_handler(sqlite3.IntegrityError)
    async def integrity_error(request,e):
        return JSONResponse({'error':{'code':'conflict','message':'Conflicting resource'}},status_code=409)
    def auth(request,kind):
        header=request.headers.get('authorization','')
        if not header.startswith('Bearer '): raise HTTPException(401,'Bearer token required')
        digest=token_hash(header[7:])
        configured=db.rows('SELECT value FROM meta WHERE key=?',(kind+'_token_hash',))
        expected=configured[0]['value'] if configured else service.config['auth'].get(kind+'_token_hash','')
        if kind=='route':
            rows=db.rows('SELECT name FROM routes WHERE api_key_hash=? AND enabled=1',(digest,))
            if rows: return rows[0]['name']
        elif expected and secrets.compare_digest(digest,expected): return True
        if kind=='unmatched':
            # The admin token may also manage unmatched transactions (admin UI).
            configured=db.rows('SELECT value FROM meta WHERE key=?',('admin_token_hash',))
            admin=configured[0]['value'] if configured else service.config['auth'].get('admin_token_hash','')
            if admin and secrets.compare_digest(digest,admin): return True
        raise HTTPException(403,'Token has no access')
    def transaction_filter(status,route,q,before_id):
        where=['simulated=0']; params=[]
        if status: where.append('status=?'); params.append(status)
        if route: where.append('route=?'); params.append(route)
        if q: where.append('(content LIKE ? OR code LIKE ? OR raw LIKE ? OR order_id LIKE ?)'); params.extend(['%'+q+'%']*4)
        if before_id: where.append('id<?'); params.append(before_id)
        return ' AND '.join(where),params
    def public_route(r): return {k:v for k,v in r.items() if k not in ('secret','api_key_hash')}
    @app.get('/healthz')
    async def health():
        f=service.fetcher; poll=service.config['fetch']['safety_poll_seconds']
        age=(datetime.now(timezone.utc)-datetime.fromisoformat(f.last_fetch_ok_at.replace('Z','+00:00'))).total_seconds() if f.last_fetch_ok_at else float('inf')
        down=not service.fcm.connected and time.time()-service.fcm.down_since>service.config['alerts']['fcm_down_alert_minutes']*60
        ok=not f.auth_rejected and not down and (not poll or age<=max(poll*2,1800))
        return JSONResponse(dict(ok=ok,last_fetch_ok_at=f.last_fetch_ok_at,fcm_connected=service.fcm.connected),status_code=200 if ok else 503)
    @app.get('/v1/transactions')
    def transactions(request:Request,after_id:int=0,limit:int=100):
        route=auth(request,'route')
        rows=db.rows("SELECT t.*, (SELECT json_extract(d.payload,'$.type') FROM deliveries d WHERE d.transaction_id=t.id AND d.route=? ORDER BY d.id DESC LIMIT 1) AS event_type FROM transactions t WHERE t.simulated=0 AND t.id>? AND EXISTS (SELECT 1 FROM deliveries d WHERE d.transaction_id=t.id AND d.route=?) ORDER BY t.id LIMIT ?",(route,after_id,route,max(1,min(limit,200))))
        items=[dict(transaction_payload(t), type=t['event_type']) for t in rows]
        return dict(items=items, next_after_id=items[-1]['id'] if items else after_id)
    @app.get('/v1/transactions/{id}')
    def transaction(id:int,request:Request):
        route=auth(request,'route'); rows=db.rows('SELECT * FROM transactions WHERE id=? AND route=?',(id,route))
        if not rows: raise HTTPException(404,'Transaction not found')
        rows[0]['deliveries']=db.rows('SELECT id,status,attempts,last_status_code FROM deliveries WHERE transaction_id=?',(id,))
        return rows[0]
    @app.get('/v1/unmatched')
    def unmatched(request:Request,after_id:int=0,limit:int=100,status:str='open'):
        auth(request,'unmatched')
        if status not in ('open','all'): raise HTTPException(400,'Invalid status')
        return db.rows("SELECT * FROM transactions WHERE id>? AND (status='unmatched' OR (?='all' AND (assigned_manually=1 OR status='ignored'))) ORDER BY id LIMIT ?",(after_id,status,max(1,min(limit,200))))
    @app.post('/v1/unmatched/{id}/assign')
    def assign(id:int,body:dict,request:Request):
        auth(request,'unmatched')
        with db.lock,db.conn:
            rows=db.rows('SELECT * FROM transactions WHERE id=?',(id,))
            if not rows: raise HTTPException(404,'Not found')
            tx=rows[0]
            if tx['assigned_manually'] and tx['route']==body.get('route') and tx['order_id']==body.get('order_id'): return tx
            if tx['status']!='unmatched': raise HTTPException(409,'Already resolved')
            routes=db.rows('SELECT * FROM routes WHERE name=? AND enabled=1',(body.get('route'),))
            if not routes or not isinstance(body.get('order_id'),str) or not body['order_id']: raise HTTPException(400,'Invalid assignment')
            code=routes[0]['prefix']+body['order_id']
            tx.update(status='matched',route=body['route'],order_id=body['order_id'],code=code,codes_json=json.dumps([code]),assigned_manually=1)
            db.conn.execute("UPDATE transactions SET status='matched',route=?,order_id=?,code=?,codes_json=?,assigned_manually=1 WHERE id=?",(tx['route'],tx['order_id'],code,tx['codes_json'],id))
            queue(db,tx)
            return tx
    @app.post('/v1/unmatched/{id}/ignore')
    def ignore(id:int,body:dict,request:Request):
        auth(request,'unmatched')
        with db.lock,db.conn:
            rows=db.rows('SELECT status FROM transactions WHERE id=?',(id,))
            if not rows: raise HTTPException(404,'Not found')
            if rows[0]['status']!='unmatched': raise HTTPException(409,'Already resolved')
            db.conn.execute("UPDATE transactions SET status='ignored',note=? WHERE id=?",(str(body.get('note',''))[:2000],id))
        return {'ok':True}
    @app.get('/admin/routes')
    def routes(request:Request):
        auth(request,'admin'); return [public_route(r) for r in db.rows('SELECT * FROM routes')]
    @app.post('/admin/routes')
    def add(body:dict,request:Request):
        auth(request,'admin'); return create_route(db,body)
    @app.patch('/admin/routes/{name}')
    def update(name:str,body:dict,request:Request):
        auth(request,'admin'); rows=db.rows('SELECT * FROM routes WHERE name=?',(name,))
        if not rows: raise HTTPException(404,'Route not found')
        with db.lock,db.conn:
            r=rows[0]; r.update({k:v for k,v in body.items() if k in ('prefix','webhook_url','id_pattern','enabled','patterns')})
            if ('prefix' in body or 'id_pattern' in body) and 'patterns' not in body: r.pop('patterns_json',None)
            validate_route(r,db.rows('SELECT * FROM routes'))
            webhook_url(r['webhook_url'], getattr(db, 'webhook_allow_insecure', ()))
            db.conn.execute('UPDATE routes SET prefix=?,webhook_url=?,id_pattern=?,enabled=?,patterns_json=? WHERE name=?',(r['prefix'],r['webhook_url'],r['id_pattern'],r['enabled'],r['patterns_json'],name))
        return public_route(r)
    @app.delete('/admin/routes/{name}')
    def delete(name:str,request:Request):
        auth(request,'admin'); db.execute('DELETE FROM routes WHERE name=?',(name,)); return {'ok':True}
    @app.post('/admin/routes/{name}/{action}')
    def route_action(name:str,action:str,request:Request):
        auth(request,'admin')
        if not db.rows('SELECT 1 FROM routes WHERE name=?',(name,)): raise HTTPException(404,'Route not found')
        if action in ('rotate-secret','rotate-api-key'):
            token=secrets.token_urlsafe(32); field='secret' if action=='rotate-secret' else 'api_key_hash'
            db.execute(f'UPDATE routes SET {field}=? WHERE name=?',(db.encrypt_secret(name, token) if field=='secret' else token_hash(token),name))
            return {'secret' if field=='secret' else 'api_key':token}
        if action=='test':
            event='evt_'+str(uuid.uuid4())
            db.execute('INSERT INTO deliveries(route,event_id,payload,created_at,updated_at) VALUES(?,?,?,?,?)',(name,event,json.dumps({'type':'ping','event_id':event,'route':name,'simulated':False}),now(),now()))
            return {'event_id':event}
        raise HTTPException(404,'Action not found')
    @app.get('/admin/deliveries')
    def deliveries(request:Request,status:str='pending'):
        auth(request,'admin'); return db.rows('SELECT * FROM deliveries WHERE status=? ORDER BY id DESC LIMIT 200',(status,))
    @app.post('/admin/deliveries/{id}/redeliver')
    def redeliver(id:int,request:Request):
        auth(request,'admin'); db.execute("UPDATE deliveries SET status='pending',next_attempt_at=0,attempts=0 WHERE id=?",(id,)); return {'ok':True}
    @app.post('/admin/fetch')
    async def fetch(request:Request):
        auth(request,'admin'); service.fetcher.trigger('manual'); return {'queued':True}
    @app.get('/admin/status')
    def status(request:Request):
        auth(request,'admin'); f=service.fetcher
        return dict(version='0.1.0',fcm_connected=service.fcm.connected,fcm_last_message_at=service.fcm.last_message_at,last_fetch_ok_at=f.last_fetch_ok_at,last_fetch_error=f.last_fetch_error,failures=f.failures,queues=db.rows('SELECT status,count(*) AS count FROM deliveries GROUP BY status'),telegram=service.alerts.configured())
    @app.get('/admin/transactions')
    def admin_transactions(request:Request,status:str='',route:str='',q:str='',before_id:int=0,limit:int=50):
        auth(request,'admin'); where,params=transaction_filter(status,route,q,before_id)
        rows=db.rows(f'SELECT * FROM transactions WHERE {where} ORDER BY id DESC LIMIT ?',(*params,max(1,min(limit,200))))
        for r in rows: r['codes']=json.loads(r.pop('codes_json') or '[]')
        return dict(items=rows,next_before_id=rows[-1]['id'] if rows else 0)
    @app.get('/admin/transactions.csv')
    def admin_transactions_csv(request:Request,status:str='',route:str='',q:str='',limit:int=5000):
        auth(request,'admin'); where,params=transaction_filter(status,route,q,0)
        rows=db.rows(f'SELECT id,bank_time,amount,currency,direction,content,account,status,route,code,order_id,assigned_manually,note,created_at FROM transactions WHERE {where} ORDER BY id DESC LIMIT ?',(*params,max(1,min(limit,20000))))
        out=io.StringIO(); w=csv.writer(out,lineterminator='\n')
        w.writerow(['id','thoi_gian_ngan_hang','so_tien','tien_te','chieu','noi_dung','tai_khoan','trang_thai','tuyen','ma','ma_don','gan_tay','ghi_chu','nhan_luc'])
        for r in rows: w.writerow([csv_cell(r[k]) for k in ('id','bank_time','amount','currency','direction','content','account','status','route','code','order_id','assigned_manually','note','created_at')])
        return Response('﻿'+out.getvalue(),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename="giao-dich-vpbank.csv"'})
    @app.get('/admin/summary')
    def admin_summary(request:Request):
        auth(request,'admin')
        by_status=db.rows('SELECT status,count(*) AS count,coalesce(sum(amount),0) AS amount FROM transactions WHERE simulated=0 GROUP BY status')
        today=db.rows("SELECT count(*) AS count,coalesce(sum(amount),0) AS amount FROM transactions WHERE simulated=0 AND direction='in' AND status IN ('matched','unmatched') AND substr(bank_time,1,10)=strftime('%Y-%m-%d','now','+7 hours')")[0]
        return dict(by_status=by_status,today=today,open_unmatched=db.rows("SELECT count(*) AS count FROM transactions WHERE status='unmatched' AND simulated=0")[0]['count'],routes=[r['name'] for r in db.rows('SELECT name FROM routes WHERE enabled=1 ORDER BY name')])
    @app.get('/admin/')
    @app.get('/admin/ui')
    def admin_ui():
        page = Path(__file__).parent/'static'/'admin.html'
        if not page.is_file():
            raise HTTPException(404, 'Admin UI is not included in this distribution')
        return HTMLResponse(page.read_text(encoding='utf-8'))
    return app
