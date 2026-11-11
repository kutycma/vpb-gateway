"""Demo chỉ dùng loopback; không đăng ký hoặc kết nối FCM thật."""
import asyncio
import json
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
import httpx
import uvicorn
from fastapi import FastAPI,Request
from tests.fake_vpbank import app as bank
from vpb_gateway.config import load
from vpb_gateway.service import Service
from vpb_gateway.api import create_route
from vpb_gateway.webhook import signature

async def main():
    receiver=FastAPI(); received=[]; secret=''
    @receiver.post('/hook')
    async def hook(request:Request):
        body=await request.body()
        assert request.headers['x-vpg-signature']==signature(secret,request.headers['x-vpg-timestamp'],body)
        received.append(json.loads(body)); return {'ok':True}
    servers=[]; ports=[]; threads=[]
    for app in (bank,receiver):
        sock=socket.socket();sock.bind(('127.0.0.1',0));ports.append(sock.getsockname()[1])
        server=uvicorn.Server(uvicorn.Config(app,log_level='critical'));servers.append(server)
        thread=threading.Thread(target=server.run,kwargs={'sockets':[sock]},daemon=True);thread.start();threads.append(thread)
    try:
        for _ in range(200):
            if all(s.started for s in servers): break
            await asyncio.sleep(.01)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); config=root/'config.toml'
            config.write_text(f'''[storage]
db_path = "{(root/'gateway.db').as_posix()}"
state_path = "{(root/'state.json').as_posix()}"
[vpbank]
base_url = "http://127.0.0.1:{ports[0]}"
[fetch]
bootstrap = "process"
min_fetch_interval_seconds = 0
''')
            s=Service(load(config));s.state.save(key='fake',pin='fake',auth_key='fake')
            secret=create_route(s.db,dict(name='shop',prefix='DH',webhook_url=f'http://127.0.0.1:{ports[1]}/hook'))['secret']
            process=await asyncio.create_subprocess_exec(sys.executable,'-m','vpb_gateway.cli','--config',str(config),'simulate','--content','DH123','--amount','10000',stdout=asyncio.subprocess.PIPE)
            output=await process.communicate()
            assert process.returncode==0
            print(output[0].decode().strip())
            assert received[0]['simulated'] is True
            async with httpx.AsyncClient() as c:
                await c.post(f'http://127.0.0.1:{ports[0]}/mock/history',json={'account':['VPB:09/11/2026 19:46|XXXX6789|20000VND|0VND|DH456']})
            task=asyncio.create_task(s.fetcher.run())
            s.fcm.message({'data':{'type':'BALANCE_CHANGING'}})
            for _ in range(200):
                if s.fetcher.last_fetch_ok_at: break
                await asyncio.sleep(.01)
            task.cancel();await asyncio.gather(task,return_exceptions=True)
            await s.outbox.tick()
            assert len(received)==2 and received[1]['transaction']['order_id']=='456'
            print('PASS local fake VPBank + mocked FCM trigger + simulate: 2 signed webhooks received')
            await s.close()
    finally:
        for server in servers: server.should_exit=True
        for thread in threads: await asyncio.to_thread(thread.join,5)

if __name__=='__main__': asyncio.run(main())
