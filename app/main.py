from __future__ import annotations

import difflib
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote, urlsplit

import requests
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import core
from .cloud import Cloud, CloudError, pb
from .scan import LIVE, excluded
from . import worker, archive

LOGIN_ATTEMPTS = {}


@asynccontextmanager
async def lifespan(app):
    core.init()
    bootstrap = Path(os.getenv('NCB_BOOTSTRAP', '/run/secrets/bootstrap.json'))
    if bootstrap.is_file():
        incoming = json.loads(bootstrap.read_text(encoding='utf-8'))
        existing = core.get_secrets()
        core.save_secrets({k: v for k, v in incoming.items() if not existing.get(k)})
    if os.getenv('NCB_DISABLE_WORKER') != '1':
        worker.start()
    yield
    worker.stop()


app = FastAPI(title='NAS Compress Backup', version=core.VERSION, lifespan=lifespan, docs_url=None, redoc_url=None)


def session_user(request: Request):
    token = request.cookies.get('ncb_session', '')
    if not token:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    session = core.one('SELECT * FROM sessions WHERE token=? AND expires>?', (digest, core.now()))
    return core.one('SELECT id FROM admin WHERE id=1') if session else None


@app.middleware('http')
async def boundary(request: Request, call_next):
    host = request.client.host if request.client else ''
    try:
        address = ipaddress.ip_address(host)
        local = address.is_private or address.is_loopback or address.is_link_local
    except ValueError:
        local = host == 'testclient' and os.getenv('NCB_TESTING') == '1'
    if not local:
        return JSONResponse({'detail': '仅允许局域网访问'}, status_code=403)
    if request.url.path.startswith('/api/'):
        public = request.url.path in ('/api/health', '/api/auth/status', '/api/auth/setup', '/api/auth/login')
        if not public and not session_user(request):
            return JSONResponse({'detail': '请先登录'}, status_code=401)
        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            origin = request.headers.get('origin')
            if origin and urlsplit(origin).netloc != request.headers.get('host'):
                return JSONResponse({'detail': '请求来源不匹配'}, status_code=403)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['X-Frame-Options'] = 'DENY'
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request, error):
    return JSONResponse({'detail': '输入格式不正确，请检查填写内容'}, status_code=422)


@app.exception_handler(CloudError)
async def cloud_error(request, error):
    return JSONResponse({'detail': core.redact(error)}, status_code=502)


@app.exception_handler(ValueError)
async def value_error(request, error):
    return JSONResponse({'detail': core.redact(error)}, status_code=400)


def password_hash(value: str, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', value.encode(), salt.encode(), 600_000).hex()
    return salt + ':' + digest


def establish_session(response: Response):
    token = secrets.token_urlsafe(32)
    core.execute('DELETE FROM sessions WHERE expires<?', (core.now(),))
    core.execute('INSERT INTO sessions VALUES (?,?)', (hashlib.sha256(token.encode()).hexdigest(), core.now() + 7 * 86400))
    response.set_cookie('ncb_session', token, httponly=True, samesite='strict', max_age=7 * 86400)


@app.get('/api/health')
def health():
    return {'ok': True, 'version': core.VERSION}


@app.get('/api/auth/status')
def auth_status(request: Request):
    user = session_user(request)
    return {'setup_required': core.one('SELECT id FROM admin WHERE id=1') is None,
            'authenticated': bool(user)}


@app.post('/api/auth/setup')
def setup(body: dict, response: Response):
    password = str(body.get('password', ''))
    if len(password) < 8:
        raise HTTPException(400, '请填写至少8位管理密码')
    with core.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT id FROM admin WHERE id=1').fetchone():
            raise HTTPException(409, '管理员已经创建')
        db.execute('INSERT INTO admin VALUES (1,?,?)', ('admin', password_hash(password)))
    establish_session(response)
    return {'ok': True}


@app.post('/api/auth/login')
def login(body: dict, request: Request, response: Response):
    host = request.client.host
    attempts = [stamp for stamp in LOGIN_ATTEMPTS.get(host, []) if core.now() - stamp < 60]
    if len(attempts) >= 8:
        raise HTTPException(429, '尝试过于频繁，请稍后重试')
    user = core.one('SELECT * FROM admin WHERE id=1')
    supplied = str(body.get('password', ''))
    valid = user and hmac.compare_digest(password_hash(supplied, user['password'].split(':')[0]), user['password'])
    if not valid:
        LOGIN_ATTEMPTS[host] = attempts + [core.now()]
        raise HTTPException(401, '密码不正确')
    LOGIN_ATTEMPTS.pop(host, None)
    establish_session(response)
    return {'ok': True}


@app.post('/api/auth/logout')
def logout(request: Request, response: Response):
    digest = hashlib.sha256(request.cookies.get('ncb_session', '').encode()).hexdigest()
    core.execute('DELETE FROM sessions WHERE token=?', (digest,))
    response.delete_cookie('ncb_session')
    return {'ok': True}


SNAPSHOTS = {}
SNAPSHOT_LOCK = threading.RLock()


def cached(key, ttl, build):
    # Display snapshots only: archive space checks and source reads never use this cache.
    with SNAPSHOT_LOCK:
        existing = SNAPSHOTS.get(key)
        if existing and time.monotonic() - existing[0] < ttl:
            return existing[1]
        value = build()
        if len(SNAPSHOTS) >= 256:
            SNAPSHOTS.pop(next(iter(SNAPSHOTS)))
        SNAPSHOTS[key] = (time.monotonic(), value)
        return value


def task_statistics(task):
    result = {}
    upload = core.one('''SELECT COALESCE(SUM(o.size),0) total,COALESCE(SUM(o.transferred),0) transferred,
       SUM(CASE WHEN o.status='uploaded' THEN 1 ELSE 0 END) done,COUNT(*) count
       FROM objects o JOIN groups g ON g.id=o.group_id WHERE g.task_id=? AND g.run_id=?''', (task['id'], task['run_id']))
    result['upload'] = upload
    result['scan_summary'] = worker.summary(task['id'])
    result['processed'] = core.one("SELECT COUNT(*) count,COALESCE(SUM(size),0) bytes FROM scan WHERE task_id=? AND state='done' AND kind NOT IN ('unchanged','moved_from')", (task['id'],))
    result['files'] = core.one('SELECT COUNT(*) count,COALESCE(SUM(size),0) bytes,SUM(CASE WHEN present=0 THEN 1 ELSE 0 END) retained FROM files_current WHERE task_id=?', (task['id'],))
    run = core.one('SELECT started FROM runs WHERE id=?', (task['run_id'],)) if task['run_id'] else None
    result['run_started'] = run['started'] if run else None
    return result


def task_view(task: dict):
    result = dict(task)
    for field in ('roots', 'excludes', 'progress'):
        result[field] = json.loads(result[field])
    result['progress'].update(LIVE.get(result['id'], {}))
    busy = worker.task_busy(task['id'])
    result['can_remove'] = not task['operation'] or bool(task['paused'] and not busy)
    if task['paused'] and task['status']=='pausing' and not busy:
        result['status']='paused'
    if worker.ACTIVE_TASK == task['id'] and task['operation'] == 'backup' and result['status'] == 'queued':
        result['status'] = 'running'
    stamp = (str(core.DB), task['id'], task['run_id'], task['scan_id'], task['catalog_generation'], task['status'], task['last_success'])
    result.update(cached(stamp, 3 if task['operation'] else 30, lambda: task_statistics(task)))
    values = core.get_secrets()
    custom = bool(values.get('task_password:' + task['id']))
    result['next_run_at'] = worker.next_due(task) if task['auto'] and task['initialized'] else None
    active = core.one('SELECT name,progress FROM tasks WHERE id=?', (worker.ACTIVE_TASK,)) if worker.ACTIVE_TASK and worker.ACTIVE_TASK != task['id'] else None
    result['waiting_for'] = active['name'] if active and task['operation'] and task['status'] == 'queued' else None
    result['encryption'] = {'enabled': True, 'algorithm': 'AES-256', 'file_names': True,
                            'mode': 'task' if custom else 'global',
                            'configured': bool(custom or values.get('archive_password')),
                            'locked': encryption_locked(task)}
    return result


def encryption_locked(task: dict) -> bool:
    return task.get('operation') == 'backup' or bool(core.one('SELECT id FROM groups WHERE task_id=? LIMIT 1', (task['id'],)))


def set_task_encryption(task_id: str, body: dict, task: dict | None = None):
    values = core.get_secrets()
    key = 'task_password:' + task_id
    current = 'task' if values.get(key) else 'global'
    mode = body.get('encryption_mode', current)
    supplied = str(body.get('encryption_password', ''))
    if mode not in ('global', 'task'):
        raise ValueError('加密密码模式无效')
    if mode == current and not supplied:
        return
    if task and encryption_locked(task):
        raise HTTPException(409, '任务正在备份或已有归档，不能更换该任务的加密密码')
    if mode == 'task':
        if not supplied and not values.get(key):
            raise ValueError('请填写任务单独使用的加密密码')
        if supplied and len(supplied) < 8:
            raise ValueError('任务加密密码至少8位')
        if supplied:
            core.save_secrets({key: supplied})
    else:
        core.save_secrets({key: ''})


@app.get('/api/overview')
def overview():
    config = core.settings()
    return {'tasks': [task_view(t) for t in core.rows('SELECT * FROM tasks ORDER BY created')],
            'disk': {'used': cached(('disk', str(core.WORK), str(core.OUT)), 5, core.disk_used), 'quota': config['quota_gb'] * 1_000_000_000},
            'night': {'start': config['night_start'], 'end': config['night_end'], 'inside': worker.window(config)[0],
                      'enabled': config['auto_schedule'], 'timezone': 'Asia/Shanghai'},
            'version': core.VERSION}


@app.get('/api/tasks/{task_id}')
def task_detail(task_id: str):
    task = core.one('SELECT * FROM tasks WHERE id=?', (task_id,))
    if not task:
        raise HTTPException(404, '任务不存在')
    return task_view(task)


def task_values(body: dict):
    name = str(body.get('name', '')).strip()
    if not name or len(name) > 80:
        raise ValueError('请填写不超过80字的任务名称')
    source = body.get('roots', [])
    if not isinstance(source, list) or not source:
        raise ValueError('请选择来源目录')
    roots = sorted({str(core.permitted(str(p))) for p in source}, key=len)
    roots = [p for i, p in enumerate(roots) if not any(Path(q) in Path(p).parents for q in roots[:i])]
    if any(not Path(p).is_dir() for p in roots):
        raise ValueError('来源目录不存在')
    excludes = body.get('excludes', [])
    if isinstance(excludes, str):
        excludes = [p.strip() for p in excludes.splitlines() if p.strip()]
    if not isinstance(excludes, list) or len(excludes) > 100:
        raise ValueError('排除规则格式错误')
    interval = body.get('interval_days', 7)
    if isinstance(interval, bool) or not isinstance(interval, int) or not 1 <= interval <= 3650:
        raise ValueError('增量间隔必须是1至3650之间的整数天数')
    return name, roots, excludes, bool(body.get('auto', True)), interval


@app.post('/api/tasks')
def create_task(body: dict):
    name, roots, excludes, auto, interval = task_values(body)
    task_id = core.identifier()
    set_task_encryption(task_id, body)
    core.execute("INSERT INTO tasks(id,name,roots,excludes,auto,interval_days,status,operation,created,updated) VALUES (?,?,?,?,?,?,'queued','scan',?,?)",
                 (task_id, name, json.dumps(roots), json.dumps(excludes), int(auto), interval, core.now(), core.now()))
    worker.WAKE.set()
    return {'id': task_id}


@app.patch('/api/tasks/{task_id}')
def update_task(task_id: str, body: dict):
    task = task_detail(task_id)
    name, roots, excludes, auto, interval = task_values(body)
    if roots == task['roots'] and excludes == task['excludes']:
        set_task_encryption(task_id, body, task)
        core.execute('UPDATE tasks SET name=?,auto=?,interval_days=?,updated=? WHERE id=?', (name, int(auto), interval, core.now(), task_id))
        return {'ok': True}
    if task['operation']:
        raise HTTPException(409, '请先结束本次运行，再修改来源目录或排除规则')
    set_task_encryption(task_id, body, task)
    core.execute('UPDATE tasks SET name=?,roots=?,excludes=?,auto=?,interval_days=?,run_id=NULL,last_scan=NULL,status=?,updated=? WHERE id=?',
                 (name, json.dumps(roots), json.dumps(excludes), int(auto), interval, 'draft', core.now(), task_id))
    return {'ok': True}


@app.delete('/api/tasks/{task_id}')
def delete_task(task_id: str):
    with worker.CONTROL_LOCK:
        return remove_task(task_id)


def remove_task(task_id):
    task = task_detail(task_id)
    if task['operation']:
        if not task['can_remove']:
            raise HTTPException(409,'当前操作仍在收尾，请稍后移除任务')
        core.execute('UPDATE tasks SET cancel_requested=1 WHERE id=?',(task_id,))
        worker.settle_cancellations()
    with core.connect() as db:
        group_ids = [r['id'] for r in db.execute('SELECT id FROM groups WHERE task_id=?', (task_id,))]
        for group_id in group_ids:
            db.execute('DELETE FROM members WHERE group_id=?', (group_id,))
            db.execute('DELETE FROM objects WHERE group_id=?', (group_id,))
        for table in ('groups', 'scan', 'files', 'file_before', 'file_edits', 'publications', 'runs', 'logs'):
            db.execute(f'DELETE FROM {table} WHERE task_id=?', (task_id,))
        db.execute('DELETE FROM tasks WHERE id=?', (task_id,))
    for parent in (core.WORK, core.OUT):
        directory = parent / task_id
        if directory.exists():
            core.owned_remove(directory, parent)
    return {'ok': True, 'cloud_files_retained': True}


@app.post('/api/tasks/{task_id}/{action}')
def task_action(task_id: str, action: str):
    if action == 'refresh-cloud':
        return change_task_action(task_id,action)
    with worker.CONTROL_LOCK:
        worker.ALLOW_CACHE.pop(task_id,None)
        result = change_task_action(task_id,action)
        worker.ALLOW_CACHE.pop(task_id,None)
        return result


def change_task_action(task_id,action):
    task = core.one('SELECT * FROM tasks WHERE id=?', (task_id,))
    if not task:
        raise HTTPException(404, '任务不存在')
    if action == 'refresh-cloud':
        return refresh_cloud_cache(task)
    elif action == 'cancel':
        if core.one('SELECT task_id FROM publications WHERE task_id=?', (task_id,)):
            raise HTTPException(409,'索引提交正在确认或等待对账，请先重试；确认后可安全结束本次运行')
        core.execute("UPDATE tasks SET paused=1,cancel_requested=1,status='pausing',updated=? WHERE id=?", (core.now(), task_id))
        worker.settle_cancellations()
    elif action == 'pause':
        core.execute("UPDATE tasks SET paused=1,status='pausing',updated=? WHERE id=?", (core.now(), task_id))
        worker.settle_pauses()
    elif action in ('resume', 'retry'):
        core.execute("UPDATE tasks SET paused=0,status='queued',error=NULL,updated=? WHERE id=?", (core.now(), task_id))
        core.execute("UPDATE objects SET status='ready',attempts=0,retry_at=0,error=NULL WHERE status='failed' AND group_id IN (SELECT id FROM groups WHERE task_id=?)", (task_id,))
    elif action in ('scan', 'run'):
        if task['operation']:
            raise HTTPException(409, '已有运行中的任务，请先继续或暂停该任务')
        if action == 'run':
            try:
                archive.password(task_id)
            except RuntimeError:
                raise HTTPException(400, '请先为任务配置加密密码，或在设置中填写默认归档密码')
        inside, key = worker.window()
        reuse = (action == 'run' and task['status'] == 'scan_ready'
                 and json.loads(task['progress']).get('stage') == 'scan_complete')
        core.progress(task_id, 'queued', percent=None, current_path='', phase_bytes=0, phase_total=0,
                      reuse_scan_id=task['scan_id'] if reuse else None, scan_run_id=None)
        core.execute('UPDATE tasks SET operation=?,status=?,run_id=NULL,paused=0,manual=?,last_window=?,error=NULL,updated=? WHERE id=?',
                     ('scan' if action == 'scan' else 'backup', 'queued', int(action == 'run'), key if inside else task['last_window'], core.now(), task_id))
    else:
        raise HTTPException(404, '不支持的操作')
    worker.WAKE.set()
    return {'ok': True}


def refresh_cloud_cache(task: dict):
    if task['operation']:
        raise HTTPException(409, '当前任务结束后再手动刷新云端清单；运行中的上传会自行核对大小')
    cached = core.rows('SELECT path,parts FROM files_current WHERE task_id=?', (task['id'],))
    if not task['cloud_dest']:
        return {'ok': True, 'groups': 0, 'abnormal_files': 0, 'message': '尚未创建云端仓库，本次按首次备份处理'}
    group_ids = {part['group'] for f in cached for part in json.loads(f['parts'])}
    states = {}
    cloud = Cloud()
    try:
        for index, group_id in enumerate(sorted(group_ids)):
            path = task['cloud_dest'].rstrip('/') + '/groups/' + group_id
            objects = core.rows('SELECT name,size,kind FROM objects WHERE group_id=?', (group_id,))
            try:
                remote = {f.name: f.size for f in cloud.files(path, True) if not f.isDirectory}
            except CloudError as error:
                if 'NOT_FOUND' not in str(error):
                    raise
                remote = {}
            missing_data = {o['name'] for o in objects if o['kind'] == 'data' and remote.get(o['name']) != o['size']}
            missing_protection = any(remote.get(o['name']) != o['size'] for o in objects if o['kind'] != 'data')
            states[group_id] = (missing_data, missing_protection)
            core.progress(task['id'], 'cloud_refresh', percent=(index + 1) / max(len(group_ids), 1) * 100)
    finally:
        cloud.close()
    abnormal = 0
    with core.connect() as db:
        for item in cached:
            state = 'ok'
            for part in json.loads(item['parts']):
                data, protection = states.get(part['group'], (set(), False))
                if any(v in data for v in part['volumes']):
                    state = 'missing'
                    break
                if protection:
                    state = 'protection_missing'
            abnormal += state != 'ok'
            db.execute('UPDATE files SET cloud_state=? WHERE task_id=? AND path=?', (state, task['id'], item['path']))
        db.execute('UPDATE tasks SET cloud_cache_at=? WHERE id=?', (core.now(), task['id']))
    core.log(task['id'], f'已刷新云端目录元数据：{len(group_ids)} 个组，{abnormal} 个文件需处理；未下载原始文件')
    return {'ok': True, 'groups': len(group_ids), 'abnormal_files': abnormal, 'downloaded_original_files': False}


@app.get('/api/browse')
def browse(path: str = ''):
    if not path:
        return {'path': '', 'parent': None, 'entries': [{'name': str(p), 'path': str(p), 'directory': True} for p in core.ROOTS if p.is_dir()]}
    root = core.permitted(path)
    if not root.is_dir():
        raise HTTPException(400, '不是目录')
    entries = []
    try:
        for p in sorted(root.iterdir(), key=lambda p: (not p.is_dir(), p.name.casefold())):
            if p.is_symlink() or not p.is_dir():
                continue
            try:
                core.permitted(str(p))
            except ValueError:
                continue
            entries.append({'name': p.name, 'path': str(p), 'directory': True,
                            'system': p.name.startswith(('@', '.', '#'))})
    except PermissionError:
        raise HTTPException(403, '没有权限读取该目录')
    parent = str(root.parent) if any(root.parent == p or p in root.parent.parents for p in core.ROOTS) else ''
    return {'path': str(root), 'parent': parent, 'entries': entries}


@app.get('/api/tasks/{task_id}/changes')
def changes(task_id: str, page: int = 1, kind: str = 'all', search: str = ''):
    task_detail(task_id)
    clauses, args = ['task_id=?', "kind NOT IN ('unchanged','moved_from')"], [task_id]
    if kind != 'all':
        clauses.append('kind=?')
        args.append(kind)
    if search:
        clauses.append('path LIKE ?')
        args.append('%' + search[:200] + '%')
    where = ' AND '.join(clauses)
    total = core.one('SELECT COUNT(*) n FROM scan WHERE ' + where, args)['n']
    items = core.rows('SELECT path,root,relative,size,mtime_ns,kind,state,error,move_from FROM scan WHERE ' + where + ' ORDER BY path LIMIT 100 OFFSET ?', args + [max(0, page - 1) * 100])
    return {'items': items, 'total': total, 'page': page, 'page_size': 100}


@app.get('/api/tasks/{task_id}/diff')
def diff(task_id: str, path: str):
    item = core.one('SELECT * FROM scan WHERE task_id=? AND path=?', (task_id, path))
    if not item:
        raise HTTPException(404, '文件不存在于当前扫描中')
    old = core.one('SELECT * FROM files_current WHERE task_id=? AND path=?', (task_id, path))
    new = None
    source = core.permitted(path)
    if source.is_file() and source.stat().st_size <= core.TEXT_LIMIT:
        try:
            new = source.read_text(encoding='utf-8-sig')
            if '\x00' in new:
                new = None
        except (OSError, UnicodeDecodeError):
            pass
    previous = old['text_content'] if old else ''
    available = new is not None and previous is not None
    lines = list(difflib.unified_diff(previous.splitlines(), new.splitlines(), fromfile='当前已备份', tofile='NAS当前文件', lineterm=''))[:4000] if available else []
    return {'path': path, 'kind': item['kind'], 'old_size': old['size'] if old else None,
            'new_size': item['size'], 'text_available': available, 'lines': lines,
            'message': None if available else '该文件为二进制、超过512KB，或没有本地文本基线；不下载云端文件进行对比'}


@app.get('/api/tasks/{task_id}/files')
def files(task_id: str, page: int = 1, search: str = ''):
    task_detail(task_id)
    args = [task_id]
    where = 'task_id=?'
    if search:
        where += ' AND path LIKE ?'
        args.append('%' + search[:200] + '%')
    total = core.one('SELECT COUNT(*) n FROM files_current WHERE ' + where, args)['n']
    items = core.rows('SELECT path,root,relative,size,sha256,present,backed_up,parts,cloud_state FROM files_current WHERE ' + where + ' ORDER BY path LIMIT 100 OFFSET ?', args + [max(0, page - 1) * 100])
    for item in items:
        item['parts'] = json.loads(item['parts'])
    return {'items': items, 'total': total, 'page': page, 'page_size': 100}


@app.get('/api/tasks/{task_id}/locations')
def locations(task_id: str, path: str):
    task = core.one('SELECT * FROM tasks WHERE id=?', (task_id,))
    item = core.one('SELECT * FROM files_current WHERE task_id=? AND path=?', (task_id, path))
    if not task or not item:
        raise HTTPException(404, '当前备份中没有此文件')
    parts = json.loads(item['parts'])
    groups = {p['group'] for p in parts}
    protection = []
    for group_id in groups:
        protection.extend(core.rows("SELECT id,name,size,kind FROM objects WHERE group_id=? ORDER BY name", (group_id,)))
    return {'path': path, 'parts': parts, 'objects': protection, 'destination': task['cloud_dest'], 'sha256': item['sha256']}


@app.get('/api/objects/{object_id}/download')
def download(object_id: str):
    obj = core.one('SELECT o.*,g.cloud_dest FROM objects o JOIN groups g ON g.id=o.group_id WHERE o.id=?', (object_id,))
    if not obj or obj['status'] != 'uploaded':
        raise HTTPException(404, '文件尚未上传完成')
    cloud = Cloud()
    info = cloud.download_info(obj['cloud_dest'].rstrip('/') + '/' + obj['name'])
    raw = info.downloadUrlPath.replace('{SCHEME}', 'http').replace('{HOST}', urlsplit(cloud.base_url).netloc).replace('{PREVIEW}', 'false')
    url = raw if raw.startswith(('https://', 'http://')) else cloud.base_url + raw
    headers = {'Authorization': 'Bearer ' + cloud.token}
    if not url.startswith(cloud.base_url + '/'):
        raise HTTPException(502, '下载地址与已配置服务不匹配')
    def stream():
        try:
            with requests.get(url, headers=headers, stream=True, timeout=(20, 60)) as response:
                if response.status_code != 200:
                    return
                yield from response.iter_content(1024 * 1024)
        except requests.RequestException:
            core.log(None, '用户请求的压缩包下载中断', 'warning')
        finally:
            cloud.close()
    return StreamingResponse(stream(), media_type='application/octet-stream',
                             headers={'Content-Disposition': "attachment; filename*=UTF-8''" + quote(obj['name']), 'Content-Length': str(obj['size'])})


@app.get('/api/runs')
def runs(task_id: str = '', page: int = 1):
    where, args = (' WHERE r.task_id=?', [task_id]) if task_id else ('', [])
    items = core.rows('SELECT r.*,t.name FROM runs r JOIN tasks t ON t.id=r.task_id' + where + ' ORDER BY r.started DESC LIMIT 50 OFFSET ?', args + [max(0, page - 1) * 50])
    for item in items:
        item['summary'] = json.loads(item['summary'])
    return {'items': items}


@app.get('/api/logs')
def logs(task_id: str = '', after: int = 0):
    where, args = ('task_id=? AND id>?', [task_id, after]) if task_id else ('id>?', [after])
    return {'items': core.rows('SELECT * FROM logs WHERE ' + where + ' ORDER BY id DESC LIMIT 100', args)}


@app.get('/api/settings')
def get_settings():
    config = core.settings()
    values = core.get_secrets()
    return {**config, 'has_clouddrive_token': bool(values.get('clouddrive_token')),
            'has_archive_password': bool(values.get('archive_password')), 'has_bark_url': bool(values.get('bark_url')),
            'paths': {'state': core.HOST_DATA, 'work': core.HOST_WORK, 'output': core.HOST_OUT},
            'encryption_locked': bool(core.one('SELECT id FROM groups LIMIT 1'))}


@app.put('/api/settings')
def put_settings(body: dict):
    values = {k: v for k, v in body.items() if k in core.DEFAULTS}
    for name in ('night_start', 'night_end'):
        if values.get(name):
            try:
                time.strptime(values[name], '%H:%M')
            except (ValueError, TypeError):
                raise ValueError('夜间时段应为 HH:MM')
    merged = {**core.settings(), **values}
    if merged['night_start'] and merged['night_end'] and merged['night_start'] == merged['night_end']:
        raise ValueError('夜间开始和结束不能相同')
    for key, maximum in (('quota_gb', 4096), ('upload_concurrency', 2), ('cpu_threads', 1)):
        if key in values:
            try:
                values[key] = int(values[key])
            except (ValueError, TypeError):
                raise ValueError('数量设置应为整数')
            if not 1 <= values[key] <= maximum:
                raise ValueError('数量设置超出允许范围')
    if 'cloud_url' in values:
        url = urlsplit(str(values['cloud_url']))
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query:
            raise ValueError('CloudDrive2 地址只填写服务地址，令牌放在专用字段')
    if 'cloud_base' in values and any(c in str(values['cloud_base']) for c in ('/', '\\', '\x00')):
        raise ValueError('目标总目录请填写单个文件夹名称')
    secret_values = {k: str(body[k]).strip() for k in ('clouddrive_token', 'archive_password', 'bark_url') if body.get(k)}
    if 'archive_password' in secret_values and core.one('SELECT id FROM groups LIMIT 1'):
        if secret_values['archive_password'] != core.get_secrets().get('archive_password'):
            raise HTTPException(409, '已有归档使用当前密码，第一版不支持更换归档密码')
    if 'bark_url' in secret_values:
        parsed = urlsplit(secret_values['bark_url'])
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise ValueError('Bark 推送地址格式不正确')
    core.update_settings(values)
    core.save_secrets(secret_values)
    worker.WAKE.set()
    return {'ok': True}


@app.post('/api/cloud/test')
def cloud_test():
    cloud = Cloud()
    try:
        return cloud.test()
    finally:
        cloud.close()


STATIC = Path(os.getenv('NCB_STATIC', str(Path(__file__).resolve().parents[1] / 'frontend/dist')))
if STATIC.is_dir():
    if (STATIC / 'assets').is_dir():
        app.mount('/assets', StaticFiles(directory=STATIC / 'assets'), name='assets')
    @app.get('/{path:path}')
    def spa(path: str):
        return FileResponse(STATIC / 'index.html')
