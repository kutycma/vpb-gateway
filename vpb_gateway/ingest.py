import hashlib
import json
import uuid
from collections import Counter
from dataclasses import asdict
from .db import now
from .parser import parse_line
from .router import match

def transaction_payload(tx):
    fields = ('id','code','order_id','amount','currency','direction','content','account','bank_time','raw')
    result = {k:tx.get(k) for k in fields}
    result.update(uid=tx['txn_uid'], codes=json.loads(tx.get('codes_json') or '[]'), received_at=tx['created_at'], assigned_manually=bool(tx.get('assigned_manually')))
    return result


def queue(db, tx, route=None, event_type='transaction.matched'):
    event = 'evt_' + str(uuid.uuid4())
    route = route or tx['route']
    payload = dict(event_id=event, type=event_type, route=route, simulated=bool(tx.get('simulated')), transaction=transaction_payload(tx))
    db.conn.execute('INSERT INTO deliveries(transaction_id,route,event_id,payload,created_at,updated_at) VALUES(?,?,?,?,?,?)', (tx['id'],route,event,json.dumps(payload,ensure_ascii=False,separators=(',',':')),now(),now()))

def ingest(db, history, config, simulated=False, force_bootstrap=False):
    added = 0
    with db.lock, db.conn:
        bootstrap = force_bootstrap or not db.conn.execute("SELECT 1 FROM meta WHERE key='bootstrapped'").fetchone()
        routes = db.rows('SELECT * FROM routes')
        for account, lines in history.items():
            for raw, count in Counter(lines).items():
                digest = hashlib.sha256((account+'\n'+raw).encode()).hexdigest()
                old = db.conn.execute('SELECT count FROM seen_lines WHERE line_hash=?',(digest,)).fetchone()
                old = old[0] if old else 0
                for occurrence in range(old+1,count+1):
                    tx = dict(txn_uid=f'{digest}:{occurrence}',account=account,raw=raw,created_at=now(),simulated=int(simulated))
                    try:
                        tx.update(asdict(parse_line(raw,account)))
                        tx.update(match(tx['content'], routes))
                        if tx['direction']=='out' and not config['routing']['route_outgoing']: tx['status']='outgoing'
                        if bootstrap and (force_bootstrap or config['fetch']['bootstrap']=='ignore') and not simulated: tx['status']='bootstrap'
                    except (ValueError,TypeError):
                        tx.update(status='parse_error',reason='malformed_line')
                    tx['codes_json']=json.dumps(tx.pop('codes',[]))
                    keys=list(tx)
                    cursor=db.conn.execute(f"INSERT INTO transactions({','.join(keys)}) VALUES({','.join('?' for _ in keys)})",list(tx.values()))
                    tx['id']=cursor.lastrowid
                    if tx['status']=='matched': queue(db,tx)
                    elif tx['status']=='unmatched' and tx.get('reason')=='no_match':
                        target=config['routing'].get('forward_unmatched_to')
                        if target and any(r['name']==target and r['enabled'] for r in routes):
                            queue(db,tx,target,'transaction.unmatched')
                    added += 1
                db.conn.execute('INSERT INTO seen_lines VALUES(?,?,?,?) ON CONFLICT(line_hash) DO UPDATE SET count=max(count,excluded.count)',(digest,raw,count,now()))
        if not simulated: db.conn.execute("INSERT OR REPLACE INTO meta VALUES('bootstrapped','1')")
    return added
