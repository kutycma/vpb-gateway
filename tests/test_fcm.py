import asyncio
from types import SimpleNamespace
import pytest
from vpb_gateway import fcm

def test_public_stopped_without_private_fields():
    assert fcm.client_stopped(SimpleNamespace(run_state=SimpleNamespace(name='STOPPED')))
    assert not fcm.client_stopped(SimpleNamespace())

async def test_partial_start_cleanup():
    class Client:
        async def stop(self): raise RuntimeError('partially started')
    await fcm.stop_client(Client())

async def test_reconnect_resets_backoff(monkeypatch):
    delays=[]; clients=[]
    class Client:
        def __init__(self): self.index=len(clients);self.calls=0;self.run_state=SimpleNamespace(name='CREATED');clients.append(self)
        async def start(self): pass
        async def stop(self): pass
        def is_started(self):
            self.calls+=1
            connected=self.index==2 and self.calls==1
            self.run_state=SimpleNamespace(name='STARTED' if connected else 'STOPPED')
            return connected
    async def sleep(delay):
        delays.append(delay)
        if len(delays)==4: raise asyncio.CancelledError()
    monkeypatch.setattr(fcm,'make_client',lambda *a:Client())
    monkeypatch.setattr(fcm,'asyncio',SimpleNamespace(sleep=sleep))
    listener=fcm.Listener(SimpleNamespace(data={'fcm':{'present':True}}),SimpleNamespace(trigger=lambda _:None),None,None,{'alerts':{'fcm_down_alert_minutes':10}})
    with pytest.raises(asyncio.CancelledError): await listener.run()
    assert delays==[5,10,1,5]

async def test_webpush_unpadded_base64():
    import base64
    import http_ece
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    def b64(data): return base64.urlsafe_b64encode(data).decode().rstrip('=')
    receiver=ec.generate_private_key(ec.SECP256R1())
    sender=ec.generate_private_key(ec.SECP256R1())
    def public(key): return key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
    salt=b'0123456789abcdef';secret=b'fedcba9876543210'
    private=receiver.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    body=b'{"data":{"type":"BALANCE_CHANGING"}}'
    encrypted=http_ece.encrypt(body,salt=salt,private_key=sender,dh=public(receiver),auth_secret=secret,version='aesgcm')
    credentials={'keys':{'private':b64(private),'secret':b64(secret)},'gcm':{'app_id':'test'}}
    state=SimpleNamespace(data={'fcm':credentials},save=lambda **_:None)
    received=[]
    client=fcm.make_client(state,lambda message,*a:received.append(message))
    assert client._decrypt_raw_data(credentials,b64(public(sender)),b64(salt),encrypted)==body
    from firebase_messaging.proto.mcs_pb2 import DataMessageStanza
    stanza=DataMessageStanza(raw_data=encrypted,persistent_id='fake-id')
    stanza.app_data.add(key='crypto-key',value='p256ecdsa=ignored; dh='+b64(public(sender)))
    stanza.app_data.add(key='encryption',value='rs=4096; salt='+b64(salt))
    stanza.app_data.add(key='subtype',value='test')
    client._handle_data_message(stanza)
    assert received==[{'data':{'type':'BALANCE_CHANGING'}}]
    stanza.raw_data=b'corrupt'
    client._handle_data_message(stanza)
    assert received[-1]['data']['type']=='UNDECRYPTABLE'
    acknowledgements=[]
    async def acknowledge(identifier): acknowledgements.append(identifier)
    client._send_selective_ack=acknowledge
    await client._handle_message(stanza)
    assert acknowledgements==['fake-id'] and client.persistent_ids==['fake-id']

async def test_fallback_poll_cadence(monkeypatch):
    from vpb_gateway import fetcher
    clock=SimpleNamespace(value=0)
    connection=SimpleNamespace(connected=False)
    config={'fetch':{'safety_poll_seconds':900,'poll_when_fcm_down_seconds':60}}
    worker=fetcher.Fetcher(None,None,config,None)
    found=[]
    def trigger(reason):
        found.append((reason,clock.value));worker.last=clock.value
    worker.trigger=trigger
    async def sleep(seconds):
        clock.value+=seconds
        if clock.value>=125: connection.connected=True
        if clock.value>1020: raise asyncio.CancelledError()
    monkeypatch.setattr(fetcher,'time',SimpleNamespace(monotonic=lambda:clock.value))
    monkeypatch.setattr(fetcher,'asyncio',SimpleNamespace(sleep=sleep))
    with pytest.raises(asyncio.CancelledError): await worker.poll(connection)
    assert found==[('fcm_down_poll',60),('fcm_down_poll',120),('poll',1020)]

def test_upstream_logs_never_format_secrets():
    import io,logging
    stream=io.StringIO();capture=logging.StreamHandler(stream)
    fcm.log.addHandler(capture)
    try:
        record=logging.LogRecord('firebase_messaging.fcmpushclient',logging.ERROR,'',1,'Unknown error: %s, shutting down FcmPushClient.\n%s',(RuntimeError('SECRET_TOKEN'), 'SECRET_TRACE'),None)
        fcm.SafeLibraryHandler().emit(record)
        assert 'SECRET' not in stream.getvalue()
        assert 'reason=listener_error exception=RuntimeError' in stream.getvalue()
    finally: fcm.log.removeHandler(capture)

def test_runtime_cannot_rotate_registered_token():
    original={'fcm':{'registration':{'token':'original-test-token'}}}
    changes=[]
    state=SimpleNamespace(data={'fcm':original},save=lambda **value:changes.append(value))
    client=fcm.make_client(state,lambda *args:None)
    with pytest.raises(RuntimeError):
        client.credentials_updated_callback({'fcm':{'registration':{'token':'different-test-token'}}})
    assert not changes

@pytest.fixture(autouse=True)
def synthetic_firebase_config(monkeypatch):
    for key, value in {'PROJECT_ID':'example-project','APP_ID':'example-app','API_KEY':'example-only','SENDER_ID':'123456789'}.items():
        monkeypatch.setenv('VPG_FIREBASE_' + key, value)
