import asyncio
import os
import json
import logging
import time
import hashlib
from .db import now

log=logging.getLogger('vpb_gateway.fcm')
log.setLevel(logging.INFO)
if not log.handlers:
    log.addHandler(logging.StreamHandler())
log.propagate=False

class SafeLibraryHandler(logging.Handler):
    """Never format upstream messages/arguments: they may contain credentials."""
    def emit(self,record):
        template=str(record.msg)
        categories={'Unexpected exception during read':'read_error','Unknown error:':'listener_error',
                    'Received an exception logging in:':'login_error','Received login error response:':'login_rejected',
                    'Unable to connect to MCS endpoint':'connect_exhausted','Shutting down push receiver':'error_limit',
                    'Unexpected exception calling notification callback':'callback_error'}
        category=next((value for prefix,value in categories.items() if template.startswith(prefix)),None)
        if category:
            error=record.exc_info[1] if record.exc_info else next((a for a in record.args if isinstance(a,BaseException)),None)
            log.info('FCM protocol failure reason=%s exception=%s',category,type(error).__name__ if error else 'unspecified')

def token_fingerprint(credentials):
    try: return hashlib.sha256(credentials['fcm']['registration']['token'].encode()).hexdigest()[:12]
    except (KeyError,TypeError,AttributeError): return 'missing'

def client_stopped(client):
    """Use public run_state; tasks is only an optional compatibility fallback."""
    state=getattr(client,'run_state',None)
    if getattr(state,'name','') in ('STOPPED','STOPPING'):
        return True
    tasks=getattr(client,'tasks',())
    return bool(tasks) and any(t.done() for t in tasks)

async def stop_client(client):
    # 0.4.5's public stop requires start() to have initialized its locks.
    # Partially failed start must never mask cancellation or the original error.
    try:
        await asyncio.wait_for(client.stop(),10)
    except Exception:
        log.info('FCM cleanup: forced cancellation after incomplete stop')
    finally:
        tasks=getattr(client,'tasks',())
        for task in tasks:
            if not task.done(): task.cancel()
        if tasks: await asyncio.gather(*tasks,return_exceptions=True)

def make_client(state, callback, *, allow_registration=False):
    from firebase_messaging import FcmPushClient,FcmRegisterConfig
    # Keep only a static allowlist of events, never raw upstream messages/args.
    for name in ('firebase_messaging.fcmpushclient','firebase_messaging.fcmregister'):
        upstream=logging.getLogger(name)
        upstream.disabled=False;upstream.propagate=False;upstream.setLevel(logging.WARNING)
        upstream.handlers=[SafeLibraryHandler()]
    class ObservedClient(FcmPushClient):
        """Version-pinned adapter: expose protocol events without upstream payload logs."""
        @staticmethod
        def _decrypt_raw_data(credentials,crypto_key_str,salt_str,raw_data):
            # Web Push base64url is normally unpadded. Upstream 0.4.5 pads
            # persisted private/auth keys but not these two envelope fields.
            def padded(value): return value+'='*((-len(value))%4)
            return FcmPushClient._decrypt_raw_data(credentials,padded(crypto_key_str),padded(salt_str),raw_data)

        def _handle_data_message(self,message):
            try:
                # Header parameter order is not fixed. Upstream slices dh=/salt=
                # prefixes and treats the rest of the header as a base64 value.
                for field in message.app_data:
                    expected={'crypto-key':'dh','encryption':'salt'}.get(field.key)
                    if expected:
                        parts=dict(part.strip().split('=',1) for part in field.value.split(';') if '=' in part)
                        if expected in parts: field.value=expected+'='+parts[expected]
                super()._handle_data_message(message)
            except Exception as error:
                # Push is only a history-fetch signal. Do not let one bad
                # envelope terminate MCS and replay forever without an ACK.
                frames=[];tb=error.__traceback__
                while tb:
                    frames.append(tb.tb_frame.f_code.co_name+':'+str(tb.tb_lineno));tb=tb.tb_next
                headers={field.key:field.value for field in message.app_data}
                metadata=[]
                for name in ('crypto-key','encryption'):
                    for part in headers.get(name,'').split(';'):
                        key,_,value=part.strip().partition('=')
                        if key in ('dh','salt','p256ecdsa','rs'): metadata.append(key+'_length='+str(len(value)))
                encoding=headers.get('content-encoding','unknown')
                log.info('FCM envelope decode failed: %s frames=%s encoding=%s fields=%s; triggering history fetch',type(error).__name__,','.join(frames),encoding if encoding in ('aesgcm','aes128gcm') else 'unknown',','.join(metadata))
                self.callback({'data':{'type':'UNDECRYPTABLE'}},message.persistent_id,self.callback_context)

        async def _connect(self):
            log.info('FCM connecting to MCS')
            try:
                async with asyncio.timeout(20): result=await super()._connect()
            except TimeoutError:
                log.info('FCM connect failed: timeout'); return False
            log.info('FCM transport %s','connected' if result else 'failed')
            return result

        async def _handle_message(self,message):
            kind=type(message).__name__
            if kind=='LoginResponse':
                log.info('FCM login %s','rejected' if str(message.error) else 'OK')
            elif kind in ('HeartbeatPing','HeartbeatAck'):
                log.info('FCM heartbeat received: %s',kind)
            elif kind=='Close': log.info('FCM disconnect: server Close')
            elif kind=='DataMessageStanza': log.info('FCM data envelope received')
            try: await super()._handle_message(message)
            except Exception as error:
                frames=[];tb=error.__traceback__
                while tb:
                    frames.append(tb.tb_frame.f_code.co_name+':'+str(tb.tb_lineno));tb=tb.tb_next
                log.info('FCM protocol handling failed: %s.%s frames=%s',type(error).__module__,type(error).__name__,','.join(frames))
                raise

        async def _send_heartbeat(self):
            log.info('FCM heartbeat sending')
            await super()._send_heartbeat()

        async def _reset(self):
            log.info('FCM reset requested state=%s',self.run_state.name)
            await super()._reset()
            log.info('FCM reset returned state=%s',self.run_state.name)

        async def _do_writer_close(self):
            writer=self.writer
            log.info('FCM transport closing')
            try:
                async with asyncio.timeout(5): await super()._do_writer_close()
            except (TimeoutError,OSError):
                if writer: writer.transport.abort()
                log.info('FCM transport close forced after timeout/error')

    def updated(creds):
        fingerprint=token_fingerprint(creds)
        if not allow_registration and state.data.get('fcm') and fingerprint!=token_fingerprint(state.data['fcm']):
            log.info('FCM refused unexpected runtime token rotation; bank registration remains unchanged')
            raise RuntimeError('Unexpected FCM credential rotation')
        log.info('FCM credentials updated token_sha256=%s',fingerprint)
        # Runtime start() never registers. Registration CLI alone may create tokens.
        state.save(fcm=creds)
    return ObservedClient(callback,FcmRegisterConfig(project_id=os.environ['VPG_FIREBASE_PROJECT_ID'],app_id=os.environ['VPG_FIREBASE_APP_ID'],api_key=os.environ['VPG_FIREBASE_API_KEY'],messaging_sender_id=os.environ['VPG_FIREBASE_SENDER_ID']),credentials=state.data.get('fcm'),received_persistent_ids=state.data.get('fcm_persistent_ids',[]),credentials_updated_callback=updated)

class Listener:
    def __init__(self,state,fetcher,db,alerts,config):
        self.state,self.fetcher,self.db,self.alerts,self.config=state,fetcher,db,alerts,config
        self.connected=False; self.last_message_at=None; self.down_since=time.time()
    def message(self,message,persistent_id=None,context=None):
        self.last_message_at=now()
        kind=message.get('data',{}).get('type','unknown') if isinstance(message.get('data'),dict) else 'unknown'
        log.info('FCM message received type=%s',kind if kind=='BALANCE_CHANGING' else 'unknown')
        if persistent_id:
            ids=(self.state.data.get('fcm_persistent_ids',[])+[persistent_id])[-100:]
            self.state.save(fcm_persistent_ids=ids)
        self.db.event('fcm',json.dumps(message,ensure_ascii=False)[:2000])
        self.fetcher.trigger('fcm')
    async def run(self):
        delay=5
        while True:
            client=None
            try:
                if not self.state.data.get('fcm'): raise RuntimeError('Missing credentials')
                log.info('FCM listener attempt token_sha256=%s registered_token_sha256=%s',token_fingerprint(self.state.data.get('fcm')),self.state.data.get('bank_fcm_token_sha256','not_recorded')[:12])
                client=make_client(self.state,self.message)
                await client.start()
                not_started_since=time.monotonic()
                previous_state=None
                while True:
                    connected=client.is_started()
                    current_state=getattr(getattr(client,'run_state',None),'name','unknown')
                    if current_state!=previous_state:
                        log.info('FCM state=%s',current_state);previous_state=current_state
                    if connected:
                        not_started_since=time.monotonic()
                        delay=5
                        if not self.connected: self.fetcher.trigger('reconnect')
                    if self.connected and not connected:
                        self.down_since=time.time();log.info('FCM disconnected state=%s',current_state)
                    self.connected=connected
                    if not connected and time.time()-self.down_since>self.config['alerts']['fcm_down_alert_minutes']*60: await self.alerts.send('FCM disconnected')
                    if client_stopped(client):
                        reasons=[]
                        for task in getattr(client,'tasks',()):
                            if task.done():
                                error=None if task.cancelled() else task.exception()
                                reasons.append('cancelled' if task.cancelled() else type(error).__name__ if error else 'returned')
                        log.info('FCM reconnect: stopped client state=%s tasks=%s',current_state,','.join(reasons));break
                    if not connected and time.monotonic()-not_started_since>90:
                        log.info('FCM reconnect: startup/reset watchdog timeout state=%s',current_state);break
                    await asyncio.sleep(1)
            except Exception as error:
                log.info('FCM listener failed: %s',type(error).__name__)
                if time.time()-self.down_since>self.config['alerts']['fcm_down_alert_minutes']*60: await self.alerts.send('FCM unavailable; polling remains active')
            finally:
                if self.connected: self.down_since=time.time()
                self.connected=False
                if client: await stop_client(client)
            log.info('FCM reconnect attempt in %ss',delay)
            await asyncio.sleep(delay); delay=min(delay*2,300)
