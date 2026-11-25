"""LAWLY account licensing service. Run with ADMIN_SECRET and a persistent database."""
import argparse
import asyncio
import datetime as dt
import hashlib
import hmac
import json
import logging
import math
import os
from pathlib import Path
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from aiohttp import web

BASE = Path(__file__).resolve().parent
ITERATIONS = 600_000
LEASE_SECONDS = 120
log = logging.getLogger('lawly')

def now():
    return time.time()

def iso(timestamp):
    return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat().replace('+00:00', 'Z') if timestamp is not None else ''

def parse_expiry(value):
    if not value:
        return None
    parsed = dt.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.timestamp()

def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), ITERATIONS).hex()

def token_hash(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

def valid_hex(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)

class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA busy_timeout=5000')
        self.db.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, record TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, timestamp REAL, username TEXT, event TEXT)')
        self.lock = asyncio.Lock()
    def get(self, name):
        row = self.db.execute('SELECT record FROM users WHERE username=?', (name,)).fetchone()
        return json.loads(row[0]) if row else None
    def put(self, record):
        self.db.execute('INSERT INTO users VALUES (?,?) ON CONFLICT(username) DO UPDATE SET record=excluded.record', (record['username'], json.dumps(record, ensure_ascii=False)))
    def all(self):
        return [json.loads(row[0]) for row in self.db.execute('SELECT record FROM users ORDER BY username COLLATE NOCASE')]
    def event(self, username, event):
        self.db.execute('INSERT INTO events(timestamp,username,event) VALUES (?,?,?)', (now(), username, event))
        self.db.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 1000)')
    def transaction(self):
        return Transaction(self.db)

STORE=web.AppKey('store',Store)
ADMIN_SECRET=web.AppKey('admin_secret',str)
PUBLIC_URL=web.AppKey('public_url',str)
ADMINS=web.AppKey('admins',dict)
LIMITS=web.AppKey('limits',dict)
HASH_SLOTS=web.AppKey('hash_slots',asyncio.Semaphore)

class Transaction:
    def __init__(self, db): self.db = db
    def __enter__(self): self.db.execute('BEGIN IMMEDIATE')
    def __exit__(self, kind, value, trace): self.db.execute('ROLLBACK' if kind else 'COMMIT')

def account_status(record):
    status = record['status']
    if status == 'active' and record.get('expires_at') is not None and record['expires_at'] <= now():
        return 'expired'
    return status

def public(record):
    result = {key: record.get(key) for key in ('username', 'target_name', 'notes', 'products', 'created_at')}
    result.update(status=account_status(record), expires_at=iso(record.get('expires_at')), hwid_bound=bool(record.get('hwid')), hwid_preview=(record.get('hwid') or '')[:10],
                  active_session=record.get('session_until', 0) > now() and account_status(record)=='active', last_login=iso(record.get('last_login')),
                  remaining_ms=record.get('remaining_ms') if record['status'] == 'paused' else (max(0, int((record['expires_at']-now())*1000)) if record.get('expires_at') is not None else None))
    return result

async def body(request):
    try:
        data = await request.json()
        if not isinstance(data, dict): raise ValueError()
        return data
    except (ValueError, json.JSONDecodeError, UnicodeError):
        raise web.HTTPBadRequest(text='JSON inválido.') from None

def reject(code, reason, status=403):
    return web.json_response({'ok': False, 'code': code, 'reason': reason}, status=status)

def limited(request, scope, maximum=20, seconds=60):
    # Trust only the TCP peer; proxy forwarding headers are not authentication.
    key = (scope, request.remote or '-')
    buckets = request.app[LIMITS]
    if len(buckets) > 10000:
        for old in list(buckets):
            if not buckets[old] or buckets[old][-1] <= now()-seconds: del buckets[old]
        if len(buckets) > 10000: return True
    bucket = buckets[key]
    while bucket and bucket[0] <= now()-seconds: bucket.popleft()
    if len(bucket) >= maximum: return True
    bucket.append(now())
    return False

def admin(request):
    supplied = request.headers.get('X-Admin-Secret', '')
    if supplied and hmac.compare_digest(supplied.encode('utf-8'), request.app[ADMIN_SECRET].encode('utf-8')): return True
    token = request.cookies.get('lawly_admin', '')
    expiry = request.app[ADMINS].get(token_hash(token), 0) if token else 0
    if expiry <= now(): return False
    if request.method != 'GET' and request.headers.get('X-Lawly-Admin') != '1': return False
    return True

@web.middleware
async def security(request, handler):
    if request.path.startswith('/admin/') and request.path not in ('/admin/login', '/admin/logout') and not admin(request):
        return reject('ADMIN_REQUIRED', 'Acesso administrativo necessário.', 401)
    if request.method not in ('GET', 'HEAD'):
        origin = request.headers.get('Origin')
        if origin and origin.rstrip('/') != (request.app[PUBLIC_URL] or str(request.url.origin())).rstrip('/'):
            return reject('ORIGIN_REJECTED', 'Origem não autorizada.', 403)
    try:
        response = await handler(request)
    except (ValueError, TypeError, KeyError, OverflowError) as error:
        log.debug('Invalid request: %s', type(error).__name__)
        response = reject('INVALID_REQUEST', 'Confira os campos enviados.', 400)
    except sqlite3.Error:
        log.error('Falha no armazenamento; operação não confirmada.')
        response = reject('STORAGE_UNAVAILABLE', 'Armazenamento indisponível.', 503)
    response.headers.update({'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
    return response

async def auth(request):
    if limited(request, 'auth-global', 600): return reject('RATE_LIMITED', 'Muitas tentativas. Aguarde um minuto.', 429)
    data = await body(request)
    username, hwid, client, product = (data.get(k, '') for k in ('username', 'hwid', 'client_id', 'product'))
    limiter_user=username if isinstance(username,str) and len(username)<=128 else '<invalid>'
    if limited(request, ('auth-user',limiter_user), 20): return reject('RATE_LIMITED', 'Muitas tentativas. Aguarde um minuto.', 429)
    if not isinstance(username, str) or not 1 <= len(username) <= 128 or not valid_hex(hwid) or not valid_hex(client) or not isinstance(product, str) or not product:
        return reject('INVALID_REQUEST', 'Credenciais, produto ou identificação inválidos.', 400)
    store = request.app[STORE]
    async with store.lock: record = store.get(username)
    session = data.get('session_token', '')
    password = data.get('password', '')
    if not isinstance(password, str) or len(password) > 512 or not isinstance(session, str) or len(session) > 256:
        return reject('INVALID_REQUEST', 'Credenciais inválidas.', 400)
    if session:
        credential_ok = record is not None and hmac.compare_digest(token_hash(session), record.get('session_hash', ''))
    else:
        # Unknown accounts pay the same password derivation cost.
        salt = record['salt'] if record else '00'*32
        async with request.app[HASH_SLOTS]:
            digest = await asyncio.to_thread(password_hash, password, salt)
        credential_ok = bool(record and hmac.compare_digest(digest, record['password_hash']))
    if not credential_ok: return reject('AUTH_INVALID_CREDENTIALS', 'Usuário ou senha incorretos.')
    async with store.lock:
        with store.transaction():
            fresh = store.get(username)
            if fresh is None or (session and not hmac.compare_digest(token_hash(session), fresh.get('session_hash', ''))) or (not session and fresh['password_hash'] != record['password_hash']):
                return reject('AUTH_INVALID_CREDENTIALS', 'Acesso alterado. Entre novamente.')
            record = fresh
            state = account_status(record)
            if state != 'active':
                record.pop('session_hash', None);record['session_until'] = 0;store.put(record)
                return reject('AUTH_USER_'+state.upper(), {'paused':'Conta pausada.','revoked':'Conta revogada.','expired':'Assinatura expirada.'}.get(state, 'Conta indisponível.'))
            if product not in record['products']: return reject('AUTH_NO_PERMISSION', 'Sua conta não possui acesso a este produto.')
            if record.get('hwid') and record['hwid'] != hwid: return reject('AUTH_HWID_MISMATCH', 'Esta conta está vinculada a outra máquina.')
            if session:
                if record.get('client_id') != client or record.get('session_until', 0) <= now(): return reject('AUTH_SESSION_EXPIRED', 'Sessão expirada. Entre novamente.')
                if data.get('logout') is True:
                    record.pop('session_hash', None);record['session_until'] = 0;store.put(record);return web.json_response({'ok':True,'code':'AUTH_LOGGED_OUT'})
                token = session
            else:
                if record.get('session_until', 0) > now() and record.get('client_id') != client: return reject('AUTH_SESSION_ACTIVE', 'Esta conta já está em uso. Aguarde encerrar a sessão anterior.')
                token = secrets.token_urlsafe(32);record['session_hash'] = token_hash(token);record['last_login'] = now();store.event(username, 'login')
            record['hwid'] = hwid;record['client_id'] = client;record['session_until'] = now()+LEASE_SECONDS;store.put(record)
            ttl = min(LEASE_SECONDS, record['expires_at']-now()) if record.get('expires_at') is not None else LEASE_SECONDS
            return web.json_response({'ok':True,'code':'AUTH_OK','reason':'Autenticado.','session_token':token,'expires_in':max(0,int(ttl)), 'expires_at':iso(record.get('expires_at')), 'permissions':record['products']})

async def admin_login(request):
    if limited(request, 'admin', 8): return reject('RATE_LIMITED','Aguarde um minuto.',429)
    data = await body(request)
    supplied = data.get('secret', '')
    if not isinstance(supplied,str) or not hmac.compare_digest(supplied.encode('utf-8'), request.app[ADMIN_SECRET].encode('utf-8')): return reject('ADMIN_INVALID','Chave administrativa inválida.',401)
    sessions = request.app[ADMINS]
    for key in list(sessions):
        if sessions[key] <= now(): del sessions[key]
    if len(sessions) >= 100: return reject('RATE_LIMITED','Muitas sessões administrativas.',429)
    token = secrets.token_urlsafe(32);sessions[token_hash(token)] = now()+8*3600
    response = web.json_response({'ok':True});response.set_cookie('lawly_admin',token,httponly=True,secure=request.secure or request.app[PUBLIC_URL].startswith('https://'),samesite='Strict',max_age=8*3600,path='/');return response

async def admin_logout(request):
    request.app[ADMINS].pop(token_hash(request.cookies.get('lawly_admin','')),None)
    response = web.json_response({'ok':True});response.del_cookie('lawly_admin',path='/');return response

async def users(request):
    store = request.app[STORE]
    if request.method == 'GET':
        async with store.lock: records = [public(r) for r in store.all()]
        return web.json_response({'users':records})
    data = await body(request);username = data.get('username','');password = data.get('password','')
    if not isinstance(username,str): raise ValueError()
    username=username.strip()
    products = data.get('products',['LAWLY'])
    if not isinstance(username,str) or not 3 <= len(username) <= 128 or not isinstance(password,str) or not 8 <= len(password) <= 512 or not isinstance(products,list) or not products or len(products)>32 or any(not isinstance(p,str) or not p.strip() or len(p)>80 for p in products):
        return reject('INVALID_REQUEST','Use usuário de 3–128 caracteres, senha de 8–512 e pelo menos um produto.',400)
    if data.get('duration_days') is not None:
        days = float(data['duration_days'])
        if not math.isfinite(days) or days<=0 or days>36500: raise ValueError()
        expiry = now()+days*86400
    else: expiry = parse_expiry(data.get('expires_at',''))
    salt = secrets.token_hex(32);digest = await asyncio.to_thread(password_hash,password,salt)
    record = {'username':username,'password_hash':digest,'salt':salt,'products':list(dict.fromkeys(p.strip() for p in products)), 'status':'active','expires_at':expiry,'created_at':iso(now()),'target_name':str(data.get('target_name',''))[:200], 'notes':str(data.get('notes',''))[:2000], 'session_until':0}
    async with store.lock:
        with store.transaction():
            if store.get(username): return reject('USER_EXISTS','Usuário já existe.',409)
            store.put(record);store.event(username,'created')
    return web.json_response({'ok':True,'record':public(record)},status=201)

async def action(request):
    data = await body(request);username = data.get('username','');operation = request.match_info['action'];store = request.app[STORE]
    if not isinstance(username,str) or not 1<=len(username)<=128: raise ValueError()
    new_password = data.get('password','')
    digest = salt = None
    if operation == 'password':
        if not isinstance(new_password,str) or not 8<=len(new_password)<=512: raise ValueError()
        salt=secrets.token_hex(32);digest=await asyncio.to_thread(password_hash,new_password,salt)
    async with store.lock:
        with store.transaction():
            record = store.get(username)
            if not record: return reject('USER_NOT_FOUND','Usuário não encontrado.',404)
            if operation == 'delete': store.db.execute('DELETE FROM users WHERE username=?',(username,));store.event(username,'deleted');return web.json_response({'ok':True})
            if operation == 'pause':
                if record['status'] != 'active': return reject('INVALID_STATE','A conta não está ativa.',409)
                record['remaining_ms'] = max(0,(record['expires_at']-now())*1000) if record.get('expires_at') is not None else None;record['status']='paused'
            elif operation == 'resume':
                if record['status'] != 'paused': return reject('INVALID_STATE','A conta não está pausada.',409)
                remaining=record.pop('remaining_ms',None);record['expires_at']=now()+remaining/1000 if remaining is not None else None;record['status']='active'
            elif operation == 'revoke': record['status']='revoked'
            elif operation == 'hwid-reset': record.pop('hwid',None)
            elif operation == 'password': record['salt']=salt;record['password_hash']=digest
            elif operation == 'edit':
                products=data.get('products',record['products'])
                if not isinstance(products,list) or not products or len(products)>32 or any(not isinstance(p,str) or not p.strip() or len(p)>80 for p in products): raise ValueError()
                record['products']=list(dict.fromkeys(p.strip() for p in products));record['notes']=str(data.get('notes',record['notes']))[:2000];record['target_name']=str(data.get('target_name',record['target_name']))[:200]
                if 'expires_at' in data: record['expires_at']=parse_expiry(data['expires_at']);record['status']='active'
            else: return reject('UNKNOWN_ACTION','Ação desconhecida.',404)
            record.pop('session_hash',None);record['session_until']=0;store.put(record);store.event(username,operation)
    return web.json_response({'ok':True,'record':public(record)})

async def stats(request):
    store=request.app[STORE]
    async with store.lock:
        records=store.all();events=[{'timestamp':r[0],'username':r[1],'event':r[2]} for r in store.db.execute('SELECT timestamp,username,event FROM events ORDER BY id DESC LIMIT 50')]
    counts={s:sum(account_status(r)==s for r in records) for s in ('active','paused','revoked','expired')}
    return web.json_response({'total':len(records),'counts':counts,'sessions':sum(r.get('session_until',0)>now() and account_status(r)=='active' for r in records),'events':events})

async def backup(request):
    store=request.app[STORE]
    async with store.lock:
        records=store.all()
        for record in records:
            for field in ('session_hash','client_id','session_until'): record.pop(field,None)
    response=web.json_response({'version':1,'users':records});response.headers['Content-Disposition']='attachment; filename="lawly-backup.json"';return response

async def health(request): return web.json_response({'status':'ok','service':'LAWLY Licenses'})
async def panel(request): return web.FileResponse(BASE/'static'/'admin.html')
async def cleanup(app): app[STORE].db.close()

def create_app(database=None, secret=None):
    secret = secret or os.environ.get('ADMIN_SECRET','')
    if len(secret)<24: raise RuntimeError('Defina ADMIN_SECRET com pelo menos 24 caracteres aleatórios.')
    app=web.Application(middlewares=[security],client_max_size=64*1024)
    app[PUBLIC_URL]=os.environ.get('PUBLIC_URL','').rstrip('/');app[STORE]=Store(database or os.environ.get('DATABASE_PATH',str(BASE/'data'/'licenses.db')));app[ADMIN_SECRET]=secret;app[ADMINS]={};app[LIMITS]=defaultdict(deque);app[HASH_SLOTS]=asyncio.Semaphore(4)
    app.router.add_get('/',health);app.router.add_get('/health',health);app.router.add_post('/auth',auth)
    app.router.add_get('/admin',panel);app.router.add_get('/admin/',panel);app.router.add_post('/admin/login',admin_login);app.router.add_post('/admin/logout',admin_logout)
    app.router.add_get('/admin/users',users);app.router.add_post('/admin/users',users);app.router.add_get('/admin/stats',stats);app.router.add_get('/admin/backup',backup);app.router.add_post('/admin/users/{action}',action)
    app.router.add_static('/static/',BASE/'static',show_index=False);app.on_cleanup.append(cleanup);return app

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--host',default=os.environ.get('HOST','127.0.0.1'));parser.add_argument('--port',type=int,default=int(os.environ.get('PORT','8080')));parser.add_argument('--database',default=os.environ.get('DATABASE_PATH',str(BASE/'data'/'licenses.db')));parser.add_argument('--verbose',action='store_true');args=parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    web.run_app(create_app(args.database),host=args.host,port=args.port,access_log=None,print=lambda message:log.info('Servidor LAWLY iniciado na porta %d.',args.port))
if __name__=='__main__': main()
