import argparse
import asyncio
import getpass
import json
import secrets
import sys
import uuid
from datetime import datetime,timedelta,timezone
from .config import load
from .service import Service
from .api import app_for,create_route
from .router import token_hash,validate_route
from .ingest import ingest
from .parser import parse_line
from .security import webhook_url

def parser():
    p=argparse.ArgumentParser(description='VPBank notification gateway')
    p.add_argument('--config'); sub=p.add_subparsers(dest='command',required=True)
    for name in ('run','doctor','prune'): sub.add_parser(name)
    r=sub.add_parser('register'); r.add_argument('--key',required=True); r.add_argument('--pin-stdin',action='store_true')
    f=sub.add_parser('fetch-once'); f.add_argument('--dry-run',action='store_true')
    r=sub.add_parser('routes'); rs=r.add_subparsers(dest='action',required=True)
    for name in ('add','update'):
        x=rs.add_parser(name); x.add_argument('--name',required=True); x.add_argument('--prefix'); x.add_argument('--pattern',action='append'); x.add_argument('--webhook',required=name=='add'); x.add_argument('--id-pattern')
    rs.add_parser('list')
    for name in ('enable','disable','delete'):
        rs.add_parser(name).add_argument('name')
    t=sub.add_parser('tokens'); t.add_argument('kind',choices=['admin','unmatched'])
    d=sub.add_parser('deliveries'); d.add_argument('action',choices=['list','redeliver']); d.add_argument('id',nargs='?',type=int)
    s=sub.add_parser('simulate'); s.add_argument('--content',required=True); s.add_argument('--amount',required=True,type=int)
    return p

async def execute(a,c):
    s=Service(c)
    try:
        db=s.db
        if a.command=='prune':
            db.prune(); print('Retention applied')
        elif a.command=='register':
            from .fcm import make_client
            pin=sys.stdin.readline().strip() if a.pin_stdin else getpass.getpass('PIN: ')
            await s.bank.validate(a.key,pin)
            client=make_client(s.state,lambda *args:None,allow_registration=True)
            token=await client.checkin_or_register()
            import hashlib
            s.state.save(fcm=client.credentials,key=a.key,pin=pin,auth_key=await s.bank.register(a.key,pin,token),bank_fcm_token_sha256=hashlib.sha256(token.encode()).hexdigest())
            ingest(db,await s.bank.fetch_history(),c,force_bootstrap=True)
            print('Registered; bootstrap complete')
        elif a.command=='doctor':
            failed=not bool(s.state.data.get('auth_key'))
            print('PASS config; PASS database; '+('PASS' if s.state.data.get('auth_key') else 'FAIL')+' state')
            try:
                if s.state.data.get('auth_key'):
                    await s.bank.fetch_history(); print('PASS reachability, JSON/WAF, history authentication')
                else:
                    await s.bank.request('GetNonSecureNotificationShare')
                    print('PASS bank endpoint reachable, JSON response; history authentication requires register')
            except Exception as e:
                failed=True; print('FAIL history: '+type(e).__name__)
            if s.state.data.get('fcm'):
                from .fcm import make_client
                client=make_client(s.state,lambda *args:None)
                try:
                    await client.start()
                    async with asyncio.timeout(30):
                        while not client.is_started(): await asyncio.sleep(.2)
                    print('PASS FCM connection')
                except Exception:
                    failed=True; print('FAIL FCM connection; check outbound TCP 5228 and registration')
                finally: await client.stop()
            else:
                failed=True; print('FAIL FCM credentials missing; run register')
                try:
                    async with asyncio.timeout(15):
                        reader,writer=await asyncio.open_connection('mtalk.google.com',5228,ssl=True,happy_eyeballs_delay=.25)
                    writer.close()
                    # MCS may not complete TLS shutdown before application login;
                    # a successful handshake already proves transport reachability.
                    try: await asyncio.wait_for(writer.wait_closed(),2)
                    except (TimeoutError,OSError): pass
                    print('PASS FCM TLS transport; authenticated messaging requires register')
                except Exception: print('FAIL FCM TLS transport; check outbound TCP 5228')
            if failed: raise RuntimeError('Doctor checks failed')
        elif a.command=='fetch-once':
            history=await s.bank.fetch_history()
            if a.dry_run:
                for account,lines in history.items():
                    for raw in lines:
                        try: print(parse_line(raw,account))
                        except ValueError: print('parse_error')
            else: print('New transactions:',ingest(db,history,c))
        elif a.command=='tokens':
            token=secrets.token_urlsafe(32); db.execute('INSERT OR REPLACE INTO meta VALUES(?,?)',(a.kind+'_token_hash',token_hash(token))); print(token)
        elif a.command=='routes':
            if a.action=='list': print(json.dumps([{k:v for k,v in r.items() if k not in ('secret','api_key_hash')} for r in db.rows('SELECT * FROM routes')]))
            elif a.action=='add':
                r=dict(name=a.name,prefix=a.prefix,webhook_url=a.webhook)
                if a.id_pattern: r['id_pattern']=a.id_pattern
                if a.pattern: r['patterns']=[dict(zip(('prefix','id_pattern'),p.split(':',1))) for p in a.pattern]
                print(json.dumps(create_route(db,r)))
            elif a.action=='update':
                r=db.rows('SELECT * FROM routes WHERE name=?',(a.name,))[0]
                for field,value in [('prefix',a.prefix),('webhook_url',a.webhook),('id_pattern',a.id_pattern)]:
                    if value is not None: r[field]=value
                if a.pattern: r['patterns']=[dict(zip(('prefix','id_pattern'),p.split(':',1))) for p in a.pattern]
                elif a.prefix or a.id_pattern: r.pop('patterns_json',None)
                validate_route(r,db.rows('SELECT * FROM routes'))
                webhook_url(r['webhook_url'], db.webhook_allow_insecure)
                db.execute('UPDATE routes SET prefix=?,webhook_url=?,id_pattern=?,patterns_json=? WHERE name=?',(r['prefix'],r['webhook_url'],r['id_pattern'],r['patterns_json'],a.name))
            elif a.action=='delete': db.execute('DELETE FROM routes WHERE name=?',(a.name,))
            else: db.execute('UPDATE routes SET enabled=? WHERE name=?',(int(a.action=='enable'),a.name))
        elif a.command=='deliveries':
            if a.action=='list': print(json.dumps(db.rows('SELECT id,route,status,attempts FROM deliveries ORDER BY id DESC LIMIT 200')))
            elif a.id is None: raise ValueError('Delivery ID required')
            else: db.execute("UPDATE deliveries SET status='pending',attempts=0,next_attempt_at=0 WHERE id=?",(a.id,))
        elif a.command=='simulate':
            date=datetime.now(timezone(timedelta(hours=7))).strftime('%d/%m/%Y %H:%M')
            # Unique account key prevents identical simulation runs being deduplicated.
            ingest(db,{str(uuid.uuid4()):[f'VPB:{date}|SIMULATED|{a.amount}VND|0VND|{a.content}']},c,simulated=True)
            await s.outbox.tick(); print('Simulation queued; due deliveries attempted')
    finally: await s.close()

def main():
    a=parser().parse_args()
    try:
        c=load(a.config)
        if a.command=='run':
            import uvicorn
            s=Service(c); uvicorn.run(app_for(s,s.lifespan),host=c['server']['host'],port=c['server']['port'],access_log=False)
        else: asyncio.run(execute(a,c))
    except Exception as e:
        print('Operation failed: '+type(e).__name__+'. Check configuration and run doctor.',file=sys.stderr); sys.exit(1)

if __name__=='__main__': main()
