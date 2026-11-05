from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DATA = Path(os.getenv('NCB_DATA', '/data'))
WORK = Path(os.getenv('NCB_WORK', '/work'))
OUT = Path(os.getenv('NCB_OUT', '/output'))
ROOTS = [Path(p).resolve() for p in os.getenv('NCB_ROOTS', '/volume1,/volume2').split(',') if p]
HOST_DATA = os.getenv('NCB_HOST_DATA', '/volume2/docker/nas-compress-backup')
HOST_WORK = os.getenv('NCB_HOST_WORK', '/volume1/暂时上传/.working/nas-compress-backup')
HOST_OUT = os.getenv('NCB_HOST_OUT', '/volume1/暂时上传/nas-compress-backup')
DB = DATA / 'state.sqlite3'
SECRET_FILE = DATA / 'secrets.json'
SECRET_LOCK = threading.RLock()
MAX_UPLOAD = int(os.getenv('NCB_MAX_UPLOAD_BYTES', '3900000000'))
PACK_PAYLOAD = int(os.getenv('NCB_PACK_BYTES', '3700000000'))
GROUP_PACKS = int(os.getenv('NCB_GROUP_PACKS', '5'))
PACK_FILES = 4096
TEXT_LIMIT = 512 * 1024
VERSION = '0.2.3'

DEFAULTS = {
    'night_start': '', 'night_end': '', 'quota_gb': 128,
    'cloud_url': 'http://127.0.0.1:19798', 'cloud_root': '',
    'cloud_base': '群晖压缩备份', 'local_source': '',
    'auto_schedule': True, 'notifications': True,
    'upload_concurrency': 1, 'cpu_threads': 1,
}


def now() -> float:
    return time.time()


def init():
    for path in (DATA, WORK, OUT):
        path.mkdir(parents=True, exist_ok=True)
    try:
        DATA.chmod(0o700)
    except OSError:
        pass
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS admin(id INTEGER PRIMARY KEY CHECK(id=1),username TEXT,password TEXT);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS tasks(
          id TEXT PRIMARY KEY,name TEXT NOT NULL,roots TEXT NOT NULL,excludes TEXT NOT NULL DEFAULT '[]',
          auto INTEGER NOT NULL DEFAULT 1,initialized INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL DEFAULT 'draft',operation TEXT,manual INTEGER NOT NULL DEFAULT 0,
          paused INTEGER NOT NULL DEFAULT 0,cloud_dest TEXT,run_id TEXT,
          progress TEXT NOT NULL DEFAULT '{}',last_scan REAL,last_success REAL,last_window TEXT,
          scan_id TEXT,error TEXT,catalog_generation INTEGER NOT NULL DEFAULT 0,
          cancel_requested INTEGER NOT NULL DEFAULT 0,
          cloud_cache_at REAL,
          interval_days INTEGER NOT NULL DEFAULT 7,last_completed REAL,
          created REAL NOT NULL,updated REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS files(
          task_id TEXT NOT NULL,path TEXT NOT NULL,root TEXT,relative TEXT,size INTEGER,
          mtime_ns INTEGER,ctime_ns INTEGER,sha256 TEXT,parts TEXT NOT NULL DEFAULT '[]',
          present INTEGER NOT NULL DEFAULT 1,backed_up REAL,text_content TEXT,
          cloud_state TEXT NOT NULL DEFAULT 'ok',
          PRIMARY KEY(task_id,path));
        CREATE TABLE IF NOT EXISTS scan(
          task_id TEXT NOT NULL,path TEXT NOT NULL,root TEXT,relative TEXT,size INTEGER,
          mtime_ns INTEGER,ctime_ns INTEGER,kind TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending',
          sha256 TEXT,text_content TEXT,offset INTEGER NOT NULL DEFAULT 0,
          staged_parts TEXT NOT NULL DEFAULT '[]',move_from TEXT,error TEXT,
          PRIMARY KEY(task_id,path));
        CREATE TABLE IF NOT EXISTS groups(
          id TEXT PRIMARY KEY,task_id TEXT NOT NULL,run_id TEXT,status TEXT NOT NULL,
          directory TEXT NOT NULL,cloud_dest TEXT,created REAL NOT NULL,error TEXT);
        CREATE TABLE IF NOT EXISTS objects(
          id TEXT PRIMARY KEY,group_id TEXT NOT NULL,name TEXT NOT NULL,size INTEGER NOT NULL,
          sha256 TEXT,kind TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'ready',
          transferred INTEGER NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,
          retry_at REAL NOT NULL DEFAULT 0,copy_source TEXT,error TEXT);
        CREATE TABLE IF NOT EXISTS members(
          group_id TEXT NOT NULL,pack TEXT NOT NULL,path TEXT NOT NULL,entry TEXT NOT NULL,
          offset INTEGER NOT NULL,length INTEGER NOT NULL,sha256 TEXT NOT NULL,final INTEGER NOT NULL,
          PRIMARY KEY(group_id,pack,path,offset));
        CREATE TABLE IF NOT EXISTS runs(
          id TEXT PRIMARY KEY,task_id TEXT NOT NULL,started REAL NOT NULL,finished REAL,
          status TEXT NOT NULL,summary TEXT NOT NULL DEFAULT '{}',error TEXT);
        CREATE TABLE IF NOT EXISTS logs(
          id INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT,run_id TEXT,at REAL NOT NULL,
          level TEXT NOT NULL,message TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS notifications(key TEXT PRIMARY KEY,last_sent REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS scan_pending ON scan(task_id,state,kind);
        CREATE INDEX IF NOT EXISTS group_tasks ON groups(task_id,status);
        CREATE INDEX IF NOT EXISTS object_groups ON objects(group_id,status);
        CREATE INDEX IF NOT EXISTS log_tasks ON logs(task_id,id);
        ''')
        task_columns = {r['name'] for r in db.execute('PRAGMA table_info(tasks)')}
        if 'cancel_requested' not in task_columns:
            db.execute('ALTER TABLE tasks ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0')
        if 'cloud_cache_at' not in task_columns:
            db.execute('ALTER TABLE tasks ADD COLUMN cloud_cache_at REAL')
        if 'interval_days' not in task_columns:
            db.execute('ALTER TABLE tasks ADD COLUMN interval_days INTEGER NOT NULL DEFAULT 7')
        if 'last_completed' not in task_columns:
            db.execute('ALTER TABLE tasks ADD COLUMN last_completed REAL')
            db.execute("""UPDATE tasks SET last_completed=COALESCE(
                (SELECT MAX(finished) FROM runs WHERE runs.task_id=tasks.id AND status IN ('complete','attention')),
                last_success)""")
        file_columns = {r['name'] for r in db.execute('PRAGMA table_info(files)')}
        if 'cloud_state' not in file_columns:
            db.execute("ALTER TABLE files ADD COLUMN cloud_state TEXT NOT NULL DEFAULT 'ok'")
        db.execute('CREATE INDEX IF NOT EXISTS file_content ON files(task_id,sha256,cloud_state)')
        db.execute('CREATE INDEX IF NOT EXISTS run_tasks ON runs(task_id,started DESC)')
        db.execute('CREATE TABLE IF NOT EXISTS file_before AS SELECT * FROM files WHERE 0')
        db.execute('CREATE UNIQUE INDEX IF NOT EXISTS file_before_path ON file_before(task_id,path)')
        db.execute('CREATE TABLE IF NOT EXISTS file_edits(task_id TEXT,path TEXT,PRIMARY KEY(task_id,path))')
        db.execute('''CREATE TABLE IF NOT EXISTS publications(
          task_id TEXT PRIMARY KEY,generation INTEGER,group_id TEXT,directory TEXT,staging TEXT,
          destination TEXT,objects TEXT)''')
        db.execute('''CREATE VIEW IF NOT EXISTS files_current AS
          SELECT f.* FROM files f WHERE NOT EXISTS
            (SELECT 1 FROM file_edits e WHERE e.task_id=f.task_id AND e.path=f.path)
          UNION ALL SELECT * FROM file_before''')
        for key, value in DEFAULTS.items():
            db.execute('INSERT OR IGNORE INTO settings VALUES (?,?)', (key, json.dumps(value)))
        db.execute("INSERT OR IGNORE INTO settings VALUES ('text_cache_bytes','0')")


@contextmanager
def connect():
    db = sqlite3.connect(DB, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA busy_timeout=30000')
    db.execute('PRAGMA synchronous=FULL')
    try:
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def rows(sql: str, args=()) -> list[dict]:
    with connect() as db:
        return [dict(r) for r in db.execute(sql, args)]


def one(sql: str, args=()) -> dict | None:
    found = rows(sql, args)
    return found[0] if found else None


def execute(sql: str, args=()):
    with connect() as db:
        db.execute(sql, args)


def settings() -> dict:
    return {r['key']: json.loads(r['value']) for r in rows('SELECT * FROM settings')}


def update_settings(values: dict):
    with connect() as db:
        for key, value in values.items():
            if key in DEFAULTS:
                db.execute('INSERT OR REPLACE INTO settings VALUES (?,?)', (key, json.dumps(value)))


def get_secrets() -> dict:
    with SECRET_LOCK:
        return json.loads(SECRET_FILE.read_text()) if SECRET_FILE.exists() else {}


def save_secrets(values: dict):
    with SECRET_LOCK:
        state = get_secrets()
        state.update({k: v for k, v in values.items() if v is not None})
        temp = SECRET_FILE.with_suffix('.new')
        temp.write_text(json.dumps(state), encoding='utf-8')
        try:
            temp.chmod(0o600)
        except OSError:
            pass
        os.replace(temp, SECRET_FILE)


def redact(message: Any) -> str:
    text = str(message)
    for value in get_secrets().values():
        if isinstance(value, str) and value:
            text = text.replace(value, '[已隐藏]')
    import re
    text = re.sub(r'https?://\S+', '[链接已隐藏]', text)
    return text[:1500]


def log(task_id: str | None, message: str, level='info', run_id=None):
    execute('INSERT INTO logs(task_id,run_id,at,level,message) VALUES (?,?,?,?,?)',
            (task_id, run_id, now(), level, redact(message)))
    execute('DELETE FROM logs WHERE id < (SELECT COALESCE(MAX(id),0)-20000 FROM logs)')


def progress(task_id: str, stage: str, **values):
    task = one('SELECT progress FROM tasks WHERE id=?', (task_id,))
    current = json.loads(task['progress']) if task else {}
    current.update(values)
    current['stage'] = stage
    current['heartbeat'] = now()
    execute('UPDATE tasks SET progress=?,updated=? WHERE id=?', (json.dumps(current), now(), task_id))


def set_status(task_id: str, status: str, error=None):
    execute('UPDATE tasks SET status=?,error=?,updated=? WHERE id=?',
            (status, redact(error) if error else None, now(), task_id))


def identifier() -> str:
    return secrets.token_hex(12)


def journal_file(db, task_id, path):
    db.execute('''INSERT OR IGNORE INTO file_before SELECT * FROM files f WHERE task_id=? AND path=?
      AND NOT EXISTS (SELECT 1 FROM file_edits e WHERE e.task_id=f.task_id AND e.path=f.path)''', (task_id,path))
    db.execute('INSERT OR IGNORE INTO file_edits VALUES (?,?)', (task_id,path))


def commit_files(db, task_id):
    db.execute('DELETE FROM file_before WHERE task_id=?', (task_id,))
    db.execute('DELETE FROM file_edits WHERE task_id=?', (task_id,))


def rollback_files(db, task_id):
    db.execute('''DELETE FROM files WHERE task_id=? AND path IN
      (SELECT path FROM file_edits WHERE task_id=?)''', (task_id,task_id))
    db.execute('INSERT INTO files SELECT * FROM file_before WHERE task_id=?', (task_id,))
    commit_files(db, task_id)
    total = db.execute('SELECT COALESCE(SUM(length(CAST(text_content AS BLOB))),0) n FROM files').fetchone()['n']
    db.execute("UPDATE settings SET value=? WHERE key='text_cache_bytes'", (str(total),))


def sync_files(paths):
    for path in paths:
        with Path(path).open('r+b') as source:
            os.fsync(source.fileno())
    if os.name == 'posix':
        # Persist file entries, newly created group directories and their task parent.
        parents = {parent for p in paths for parent in list(Path(p).parents)[:3]}
        for parent in parents:
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def signature(path: Path) -> tuple[int, int, int]:
    s = path.stat()
    return s.st_size, s.st_mtime_ns, s.st_ctime_ns


def disk_used() -> int:
    size = 0
    for directory in (WORK, OUT):
        for root, dirs, names in os.walk(directory, followlinks=False):
            dirs[:] = [d for d in dirs if not Path(root, d).is_symlink()]
            for name in names:
                path = Path(root, name)
                try:
                    if not path.is_symlink():
                        size += path.stat().st_size
                except FileNotFoundError:
                    pass
    return size


def owned_remove(path: Path, parent: Path):
    import shutil
    path, parent = path.resolve(), parent.resolve()
    if path == parent or parent not in path.parents:
        raise ValueError('拒绝清理工作区之外的路径')
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def permitted(path: str) -> Path:
    target = Path(path).resolve()
    if not any(target == root or root in target.parents for root in ROOTS):
        raise ValueError('路径不在允许的卷内')
    blocked = [Path(p).resolve() for p in (HOST_DATA, HOST_WORK, HOST_OUT)]
    if any(target == p or p in target.parents for p in blocked):
        raise ValueError('本程序工作和配置目录不参与备份')
    return target
