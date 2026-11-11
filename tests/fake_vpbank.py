import json
from fastapi import FastAPI,Request
app=FastAPI()
history={}
@app.get('/cb/odata/ns/authenticationservice/ValidationNonSecureNotificationShare')
def register(request:Request):
    return {'d':{'Status':'1','Jwt':'fake-jwt'}} if request.headers.get('TokenFB') else {'d':{'Status':'2'}}
@app.get('/cb/odata/ns/authenticationservice/GetNonSecureNotificationShare')
def fetch(): return {'d':{'Status':'true','Message':json.dumps(history)}}
@app.post('/mock/history')
def update(body:dict):
    history.clear(); history.update(body); return {'ok':True}
