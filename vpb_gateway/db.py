import sqlite3
import threading
from pathlib import Path
from datetime import datetime, timezone

def now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

SCHEMA = '''
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE IF NOT EXISTS routes(name TEXT PRIMARY KEY,prefix TEXT UNIQUE,webhook_url TEXT,secret TEXT,id_pattern TEXT,enabled INTEGER DEFAULT 1,api_key_hash TEXT);
CREATE TABLE IF NOT EXISTS seen_lines(line_hash TEXT PRIMARY KEY,raw TEXT,count INTEGER,first_seen_at TEXT);
CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY,txn_uid TEXT UNIQUE,account TEXT,bank_time TEXT,amount INTEGER,currency TEXT,direction TEXT,extra TEXT,content TEXT,raw TEXT,status TEXT,reason TEXT,route TEXT,code TEXT,order_id TEXT,codes_json TEXT,assigned_manually INTEGER DEFAULT 0,note TEXT,created_at TEXT,simulated INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS deliveries(id INTEGER PRIMARY KEY,transaction_id INTEGER,route TEXT,event_id TEXT UNIQUE,payload TEXT,status TEXT DEFAULT 'pending',attempts INTEGER DEFAULT 0,next_attempt_at REAL DEFAULT 0,last_status_code INTEGER,last_error TEXT,created_at TEXT,updated_at TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,kind TEXT,message TEXT,created_at TEXT);
CREATE INDEX IF NOT EXISTS txn_route ON transactions(route,id);
CREATE INDEX IF NOT EXISTS delivery_due ON deliveries(status,next_attempt_at);
INSERT OR IGNORE INTO meta VALUES('schema_version','1');
'''

class DB:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = Path(path)
        self.cipher = None
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('PRAGMA secure_delete=ON')
        self.conn.execute('PRAGMA busy_timeout=5000')
        # Migration 001: initial schema. Refuse newer versions rather than silently
        # opening a database created by an incompatible release.
        exists=self.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone()
        if exists:
            version=self.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if version and int(version[0])>3:
                self.conn.close()
                raise ValueError('Unsupported database schema')
        self.conn.executescript(SCHEMA)
        with self.conn:
            columns = {r[1] for r in self.conn.execute('PRAGMA table_info(routes)')}
            if 'patterns_json' not in columns:
                self.conn.execute('ALTER TABLE routes ADD COLUMN patterns_json TEXT')
            self.conn.execute("UPDATE meta SET value='2' WHERE key='schema_version' AND CAST(value AS INTEGER)<2")

    def rows(self, sql, params=()):
        with self.lock:
            rows = [dict(r) for r in self.conn.execute(sql, params)]
            for row in rows:
                if self.cipher and 'secret' in row and row['secret'].startswith('aesgcm:'):
                    import base64
                    data = base64.b64decode(row['secret'][7:])
                    row['secret'] = self.cipher.decrypt(data[:12], data[12:], row['name'].encode()).decode()
            return rows

    def execute(self, sql, params=()):
        with self.lock, self.conn:
            return self.conn.execute(sql, params).lastrowid

    def event(self, kind, message):
        self.execute('INSERT INTO events(kind,message,created_at) VALUES(?,?,?)', (kind, message[:2000], now()))
        self.execute("DELETE FROM events WHERE created_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-30 days')")

    def encrypt_secret(self, name, secret):
        if not self.cipher:
            return secret
        import os, base64
        nonce = os.urandom(12)
        return 'aesgcm:' + base64.b64encode(nonce + self.cipher.encrypt(nonce, secret.encode(), name.encode())).decode()

    def configure_crypto(self, state):
        import base64, secrets
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        with self.lock:
            version = self.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
            if 'route_encryption_key' not in state.data:
                if version == '3':
                    raise ValueError('Missing route encryption key')
                state.save(route_encryption_key=base64.b64encode(secrets.token_bytes(32)).decode())
            self.cipher = AESGCM(base64.b64decode(state.data['route_encryption_key']))
            if version != '3':
                backup_dir = self.path.parent / 'backups'
                backup_dir.mkdir(mode=0o700, exist_ok=True)
                with sqlite3.connect(backup_dir / ('migration-v3-' + datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f') + '.db')) as backup:
                    self.conn.backup(backup)
                with self.conn:
                    for name, secret in self.conn.execute('SELECT name,secret FROM routes').fetchall():
                        self.conn.execute('UPDATE routes SET secret=? WHERE name=?', (self.encrypt_secret(name,secret),name))
                    self.conn.execute("UPDATE meta SET value='3' WHERE key='schema_version'")
                self.conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')

    def prune(self):
        with self.lock, self.conn:
            self.conn.execute("DELETE FROM deliveries WHERE status='success' AND updated_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-90 days')")
            self.conn.execute("DELETE FROM events WHERE created_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-30 days')")
