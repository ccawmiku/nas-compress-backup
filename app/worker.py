from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from . import core
from . import archive
from .cloud import Cloud, CloudError
from .scan import scan_task, Interrupted, LIVE

TZ = timezone(timedelta(hours=8))
WAKE = threading.Event()
STOP = threading.Event()
UPLOADS = ThreadPoolExecutor(max_workers=2, thread_name_prefix='cloud-upload')
FUTURES = {}
ACTIVE_TASK = None
CONTROL_LOCK = threading.RLock()
ALLOW_CACHE = {}


def task_busy(task_id):
    if ACTIVE_TASK == task_id:
        return True
    for object_id,future in list(FUTURES.items()):
        if not future.done() and core.one('SELECT 1 FROM objects o JOIN groups g ON g.id=o.group_id WHERE o.id=? AND g.task_id=?',(object_id,task_id)):
            return True
    return bool(core.one('SELECT 1 FROM publications WHERE task_id=?',(task_id,)))


def settle_pauses():
    with CONTROL_LOCK:
        for task in core.rows("SELECT id FROM tasks WHERE paused=1 AND status='pausing'"):
            if not task_busy(task['id']):
                core.set_status(task['id'],'paused')


def settle_cancellations():
    for task in core.rows('SELECT * FROM tasks WHERE cancel_requested=1'):
        if ACTIVE_TASK == task['id']:
            continue
        if core.one('SELECT task_id FROM publications WHERE task_id=?', (task['id'],)):
            continue
        active = False
        for object_id, future in list(FUTURES.items()):
            obj = core.one('SELECT g.task_id FROM objects o JOIN groups g ON g.id=o.group_id WHERE o.id=?', (object_id,))
            if obj and obj['task_id'] == task['id'] and not future.done():
                active = True
        if active:
            continue
        for group in core.rows("SELECT * FROM groups WHERE task_id=? AND status NOT IN ('committed','empty','retired','cancelled')", (task['id'],)):
            directory = Path(group['directory'])
            if directory.exists():
                core.owned_remove(directory, core.OUT)
            scratch = core.WORK / task['id'] / group['id']
            if scratch.exists():
                core.owned_remove(scratch, core.WORK)
            core.execute("UPDATE groups SET status='cancelled' WHERE id=?", (group['id'],))
        with core.connect() as db:
            core.rollback_files(db, task['id'])
            db.execute("UPDATE scan SET offset=0,staged_parts='[]',text_content=NULL,sha256=NULL,state='pending' WHERE task_id=? AND state!='done'", (task['id'],))
            if task['run_id']:
                db.execute("UPDATE runs SET status='stopped',finished=? WHERE id=?", (core.now(), task['run_id']))
            db.execute("UPDATE tasks SET cancel_requested=0,paused=0,operation=NULL,run_id=NULL,manual=0,status='scan_ready',error=NULL,updated=? WHERE id=?", (core.now(), task['id']))
        core.log(task['id'], '已结束本次运行，当前已提交备份和NAS原始文件保持可用')


def window(config=None, date=None) -> tuple[bool, str]:
    config = config or core.settings()
    date = date or datetime.now(TZ)
    try:
        start = datetime.strptime(config['night_start'], '%H:%M').time()
        end = datetime.strptime(config['night_end'], '%H:%M').time()
    except (ValueError, TypeError):
        return False, ''
    current = date.time().replace(tzinfo=None)
    if start == end:
        return True, date.date().isoformat()
    if start < end:
        return start <= current < end, date.date().isoformat()
    night_date = date.date() - timedelta(days=1) if current < end else date.date()
    return current >= start or current < end, night_date.isoformat()


def allowed(task_id):
    task = core.one('SELECT * FROM tasks WHERE id=?', (task_id,))
    return bool(task and not task['paused'] and not STOP.is_set() and (task['manual'] or window()[0]))


def allow_poll(task_id):
    if STOP.is_set():
        return False
    old = ALLOW_CACHE.get(task_id)
    if old and time.monotonic()-old[0]<0.25:
        return old[1]
    result = allowed(task_id)
    if len(ALLOW_CACHE)>256:
        ALLOW_CACHE.clear()
    ALLOW_CACHE[task_id]=(time.monotonic(),result)
    return result


def notify_terminal(task: dict, message: str):
    config = core.settings()
    endpoint = core.get_secrets().get('bark_url', '')
    if not config['notifications'] or not endpoint:
        return
    key = task['id'] + ':' + hashlib.sha256(message.encode()).hexdigest()[:16]
    last = core.one('SELECT * FROM notifications WHERE key=?', (key,))
    if last and core.now() - last['last_sent'] < 24 * 3600:
        return
    try:
        response = requests.post(endpoint.rstrip('/'), json={
            'title': 'NAS备份需要处理', 'body': task['name'] + '：' + core.redact(message),
            'group': 'nas-compress-backup'}, timeout=15)
        if response.status_code != 200:
            raise RuntimeError('推送服务器返回异常状态')
        core.execute('INSERT OR REPLACE INTO notifications VALUES (?,?)', (key, core.now()))
    except Exception:
        core.log(task['id'], 'Bark 通知发送失败，请检查通知设置', 'warning', task['run_id'])


def local_cloud_path(task_id: str, group_id: str, name: str) -> str:
    source = core.settings()['local_source'].rstrip('/')
    if not source:
        raise CloudError('请在设置中测试 CloudDrive2 连接')
    return source + '/nas-compress-backup/' + task_id + '/' + group_id + '/' + name


def wait_copy(cloud: Cloud, source: str, dest: str, expected: dict[str, int], on_progress=lambda value: None,
              overwrite=False):
    # Immutable objects can be reused after a restart, but not while a matching transfer is active.
    tasks = [t for t in cloud.copy_tasks() if t.sourcePath == source and t.destPath == dest]
    active = [t for t in tasks if t.status not in (3, 4)]
    remote = {f.name: f.size for f in cloud.files(dest, True) if not f.isDirectory}
    if not overwrite and not active and all(remote.get(name) == size for name, size in expected.items()):
        on_progress(sum(expected.values()))
        return
    if not active:
        cloud.start_copy(source, dest, overwrite)
    began = time.monotonic()
    last_change = began
    last_bytes = -1
    while not STOP.is_set():
        tasks = [t for t in cloud.copy_tasks() if t.sourcePath == source and t.destPath == dest]
        task = max(tasks, key=lambda t: (t.startTime.seconds, t.startTime.nanos)) if tasks else None
        if task:
            value = int(task.uploadedBytes)
            try:
                details = cloud.uploads(dest)
                value = max(value, sum(min(details.get(dest.rstrip('/') + '/' + n, {}).get('bytes', 0), s) for n, s in expected.items()))
            except CloudError:
                pass
            on_progress(min(value, sum(expected.values())))
            if value != last_bytes:
                last_bytes, last_change = value, time.monotonic()
            if task.status == 4 or task.failedFiles or task.failedFolders:
                raise CloudError('CloudDrive2 报告上传失败')
            if task.status == 3:
                remote = {f.name: f.size for f in cloud.files(dest, True) if not f.isDirectory}
                if all(remote.get(name) == size for name, size in expected.items()):
                    on_progress(sum(expected.values()))
                    return
                raise CloudError('上传结束后云端数量或大小不一致')
        if time.monotonic() - last_change > 15 * 60 or time.monotonic() - began > 24 * 3600:
            raise CloudError('上传长时间没有进展')
        STOP.wait(1.5)
    raise Interrupted('服务停止，已保留上传状态')


def upload_object(object_id: str):
    obj = core.one('SELECT * FROM objects WHERE id=?', (object_id,))
    group = core.one('SELECT * FROM groups WHERE id=?', (obj['group_id'],))
    task = core.one('SELECT * FROM tasks WHERE id=?', (group['task_id'],))
    cloud = Cloud()
    try:
        directory = Path(group['directory'])
        path = directory / obj['name']
        if not path.is_file() or path.stat().st_size != obj['size']:
            raise RuntimeError('本地待上传对象缺失，工作副本没有被确认')
        task_dest = cloud.task_destination(task)
        groups_dest = cloud.ensure_folder(task_dest, 'groups')
        destination = cloud.ensure_folder(groups_dest, group['id'])
        core.execute('UPDATE groups SET cloud_dest=? WHERE id=?', (destination, group['id']))
        source = local_cloud_path(task['id'], group['id'], obj['name'])
        core.execute("UPDATE objects SET status='uploading',copy_source=?,attempts=attempts+1 WHERE id=?", (source, object_id))
        wait_copy(cloud, source, destination, {obj['name']: obj['size']},
                  lambda n: core.execute('UPDATE objects SET transferred=? WHERE id=?', (n, object_id)))
        core.execute("UPDATE objects SET status='uploaded',transferred=size,error=NULL WHERE id=?", (object_id,))
    except Interrupted:
        core.execute("UPDATE objects SET status='ready' WHERE id=?", (object_id,))
    except Exception as error:
        current = core.one('SELECT attempts FROM objects WHERE id=?', (object_id,))
        attempts = current['attempts']
        message = core.redact(error)
        if attempts >= 3:
            core.execute("UPDATE objects SET status='failed',error=? WHERE id=?", (message, object_id))
            core.log(task['id'], '上传重试已耗尽：' + obj['name'] + '；' + message, 'error', task['run_id'])
        else:
            core.execute("UPDATE objects SET status='retry',retry_at=?,error=? WHERE id=?", (core.now() + [5, 15, 45][max(0, attempts - 1)], message, object_id))
    finally:
        cloud.close()


def pump_uploads(task_id: str, group_id: str, start=True):
    for key, future in list(FUTURES.items()):
        if future.done():
            try:
                future.result()
            except Exception as error:
                core.log(task_id, '上传工作进程异常：' + core.redact(error), 'error')
            FUTURES.pop(key)
    if not start or not allowed(task_id):
        return
    capacity = max(1, min(2, int(core.settings()['upload_concurrency']))) - len(FUTURES)
    if capacity <= 0:
        return
    objects = core.rows("SELECT id FROM objects WHERE group_id=? AND status IN ('ready','retry') AND retry_at<=? ORDER BY rowid LIMIT ?", (group_id, core.now(), capacity))
    for obj in objects:
        if obj['id'] not in FUTURES:
            FUTURES[obj['id']] = UPLOADS.submit(upload_object, obj['id'])


def apply_group(task: dict, group: dict):
    objects = core.rows("SELECT * FROM objects WHERE group_id=? AND kind='data'", (group['id'],))
    members = core.rows('SELECT * FROM members WHERE group_id=? ORDER BY path,offset', (group['id'],))
    with core.connect() as db:
        for member in members:
            item = db.execute('SELECT * FROM scan WHERE task_id=? AND path=?', (task['id'], member['path'])).fetchone()
            if not item or item['state'] in ('done', 'unstable'):
                continue
            item = dict(item)
            parts = json.loads(item['staged_parts'])
            if any(p['group'] == group['id'] and p['offset'] == member['offset'] for p in parts):
                continue
            volumes = sorted(o['name'] for o in objects if o['name'] == member['pack'] or o['name'].startswith(member['pack'] + '.'))
            parts.append({'group': group['id'], 'archive': volumes[0], 'volumes': volumes,
                          'entry': member['entry'], 'offset': member['offset'], 'length': member['length'],
                          'sha256': member['sha256']})
            parts.sort(key=lambda p: p['offset'])
            db.execute('UPDATE scan SET staged_parts=? WHERE task_id=? AND path=?', (json.dumps(parts), task['id'], item['path']))
            if member['final']:
                try:
                    if core.signature(Path(item['path'])) != (item['size'], item['mtime_ns'], item['ctime_ns']):
                        raise RuntimeError('源文件在上传期间变化')
                    position = 0
                    for part in parts:
                        if part['offset'] != position:
                            raise RuntimeError('文件分段不完整')
                        position += part['length']
                    if position != item['size']:
                        raise RuntimeError('文件长度不完整')
                    archive._record_file(db, task['id'], item, parts)
                    db.execute("UPDATE scan SET state='done',text_content=NULL WHERE task_id=? AND path=?", (task['id'], item['path']))
                except (OSError, RuntimeError) as error:
                    db.execute("UPDATE scan SET state='unstable',error=? WHERE task_id=? AND path=?", (core.redact(error), task['id'], item['path']))


def apply_deletions(task_id: str):
    with core.connect() as db:
        for row in db.execute("SELECT path FROM files WHERE task_id=? AND present=1 AND path IN (SELECT path FROM scan WHERE task_id=? AND kind='deleted')", (task_id,task_id)):
            core.journal_file(db, task_id, row['path'])
        db.execute("UPDATE files SET present=0 WHERE task_id=? AND path IN (SELECT path FROM scan WHERE task_id=? AND kind='deleted')", (task_id, task_id))
        db.execute("UPDATE scan SET state='done' WHERE task_id=? AND kind='deleted'", (task_id,))
        db.execute("UPDATE files SET present=1 WHERE task_id=? AND path IN (SELECT path FROM scan WHERE task_id=? AND kind='unchanged')", (task_id, task_id))


def publish_catalog(task: dict, cloud: Cloud, group_id=None):
    task = core.one('SELECT * FROM tasks WHERE id=?', (task['id'],))
    generation = task['catalog_generation'] + 1
    publication = str(generation) + '-' + core.identifier()
    slot = 'catalog-' + ('a' if generation % 2 else 'b')
    directory = core.OUT / task['id'] / slot
    if directory.exists():
        core.owned_remove(directory, core.OUT)
    directory.mkdir(parents=True)
    # Write the JSON incrementally. Large catalogs do not need to fit in RAM.
    staging = core.WORK / task['id'] / 'catalog'
    staging.mkdir(parents=True, exist_ok=True)
    metadata = staging / 'current-index.json'
    with metadata.open('w', encoding='utf-8') as out, core.connect() as db:
        out.write('{"format":1,"generation":' + str(generation) + ',"task":')
        json.dump({'id': task['id'], 'name': task['name'], 'roots': json.loads(task['roots'])}, out, ensure_ascii=False)
        out.write(',"files":[')
        first = True
        for row in db.execute('SELECT * FROM files WHERE task_id=? ORDER BY path', (task['id'],)):
            if not first:
                out.write(',')
            first = False
            item = dict(row)
            item.pop('text_content', None)
            item['parts'] = json.loads(item['parts'])
            json.dump(item, out, ensure_ascii=False)
        out.write(']}')
    archive_name = 'current-index-' + publication + '.7z'
    archive.seven('a', directory / archive_name, task['id'],
                  ['-t7z', '-mhe=on', '-mx=3', '-mmt=1', '-v%db' % core.MAX_UPLOAD, metadata.name], cwd=staging, stage='index')
    volumes = sorted(directory.glob(archive_name + '.*'))
    if len(volumes) == 1:
        os.replace(volumes[0], directory / archive_name)
    files = sorted(p for p in directory.iterdir() if p.is_file())
    archive.seven('t', files[0], task['id'], stage='local_verify')
    if any(p.stat().st_size > core.MAX_UPLOAD for p in files):
        raise RuntimeError('索引超过单文件大小限制')
    core.sync_files(files)
    dest = cloud.ensure_folder(cloud.task_destination(task), slot)
    # A tiny slot marker is uploaded last and binds a generation to exact encrypted objects.
    marker = directory / ('catalog-' + publication + '.json')
    marker.write_text(json.dumps({'format': 1, 'generation': generation,
        'objects': [{'name': p.name, 'size': p.stat().st_size, 'sha256': core.digest_file(p)} for p in files]}), encoding='utf-8')
    core.sync_files([marker])
    objects = [{'name': p.name,'size':p.stat().st_size} for p in [*files,marker]]
    core.execute('INSERT INTO publications VALUES (?,?,?,?,?,?,?)',
                 (task['id'],generation,group_id,str(directory),str(staging),dest,json.dumps(objects)))
    complete_publication(core.one('SELECT * FROM publications WHERE task_id=?', (task['id'],)),cloud)


def complete_publication(publication, cloud):
    task_id = publication['task_id']
    task = core.one('SELECT * FROM tasks WHERE id=?', (task_id,))
    directory,staging = Path(publication['directory']),Path(publication['staging'])
    objects = json.loads(publication['objects'])
    # The immutable receipt is last. A persisted intent allows restart to finish
    # the identical publication instead of abandoning a possibly committed receipt.
    for obj in objects:
        source = core.settings()['local_source'].rstrip('/') + '/nas-compress-backup/' + task_id + '/' + directory.name + '/' + obj['name']
        core.progress(task_id,'commit',current_path=obj['name'],percent=None,phase_bytes=0,phase_total=obj['size'])
        wait_copy(cloud,source,publication['destination'],{obj['name']:obj['size']},
                  on_progress=lambda value: core.progress(task_id,'commit',phase_bytes=value,percent=100*value/max(obj['size'],1)))
    with core.connect() as db:
        core.commit_files(db,task_id)
        db.execute('UPDATE tasks SET catalog_generation=?,cloud_cache_at=? WHERE id=?', (publication['generation'],core.now(),task_id))
        if publication['group_id']:
            db.execute("UPDATE groups SET status='committed' WHERE id=?", (publication['group_id'],))
        db.execute('DELETE FROM publications WHERE task_id=?', (task_id,))
    core.progress(task_id,'index',catalog_dirty=False)
    for path,parent in ((staging,core.WORK),(directory,core.OUT)):
        if path.exists():
            core.owned_remove(path,parent)
    if publication['group_id']:
        group = core.one('SELECT directory FROM groups WHERE id=?', (publication['group_id'],))
        for path,parent in ((Path(group['directory']),core.OUT),(core.WORK/task_id/publication['group_id'],core.WORK)):
            if path.exists():
                core.owned_remove(path,parent)
    try:
        cloud.prune_catalog(publication['destination'],{o['name'] for o in objects},task['cloud_dest'] or cloud.task_destination(task))
    except Exception:
        core.log(task_id,'当前索引已提交；旧索引残留将在后续写入同一槽位时清理','warning')


def recover_publications():
    for publication in core.rows('SELECT * FROM publications'):
        cloud = Cloud()
        try:
            complete_publication(publication,cloud)
            core.log(publication['task_id'],'已完成中断前的索引提交对账')
        finally:
            cloud.close()


def commit_group(task: dict, group: dict):
    cloud = Cloud()
    try:
        members = core.rows('SELECT * FROM objects WHERE group_id=?', (group['id'],))
        destination = core.one('SELECT cloud_dest FROM groups WHERE id=?', (group['id'],))['cloud_dest']
        remote = {f.name: f.size for f in cloud.files(destination, True) if not f.isDirectory}
        expected = {o['name']: o['size'] for o in members}
        if remote != expected:
            raise CloudError('云端恢复组文件数量或大小不一致')
        core.progress(task['id'], 'size_verify', percent=100)
        apply_group(task, group)
        apply_deletions(task['id'])
        publish_catalog(task, cloud, group['id'])
        core.owned_remove(Path(group['directory']), core.OUT)
        scratch = core.WORK / task['id'] / group['id']
        if scratch.exists():
            core.owned_remove(scratch, core.WORK)
        core.log(task['id'], '恢复组上传完成，云端数量和大小核对通过，已回收本地工作副本', run_id=task['run_id'])
    finally:
        cloud.close()


def summary(task_id):
    return {r['kind']: r['n'] for r in core.rows('SELECT kind,COUNT(*) n FROM scan WHERE task_id=? GROUP BY kind', (task_id,))}


def finish(task: dict):
    apply_deletions(task['id'])
    # Even runs containing only renames/deletions must publish the latest current index.
    cloud = Cloud()
    try:
        current = core.one('SELECT * FROM tasks WHERE id=?', (task['id'],))
        if current['catalog_generation'] == 0 or json.loads(current['progress']).get('catalog_dirty'):
            publish_catalog(task, cloud)
        collect_unused_groups(task, cloud)
    finally:
        cloud.close()
    failed = core.one("SELECT COUNT(*) n FROM scan WHERE task_id=? AND state='unstable'", (task['id'],))['n']
    status = 'attention' if failed else 'complete'
    core.execute('UPDATE runs SET status=?,finished=?,summary=? WHERE id=?', (status, core.now(), json.dumps(summary(task['id'])), task['run_id']))
    core.execute('UPDATE tasks SET status=?,operation=NULL,manual=0,last_success=CASE WHEN ?=0 THEN ? ELSE last_success END,last_completed=?,updated=? WHERE id=?',
                 (status, failed, core.now(), core.now(), core.now(), task['id']))
    core.progress(task['id'], 'complete', percent=100, current_path='')
    core.log(task['id'], f'本次运行结束，{failed} 个文件等待下次扫描' if failed else '本次运行完成，当前备份已更新', run_id=task['run_id'])


def collect_unused_groups(task: dict, cloud: Cloud):
    references = set()
    with core.connect() as db:
        for record in db.execute('SELECT parts FROM files WHERE task_id=?', (task['id'],)):
            references.update(p['group'] for p in json.loads(record['parts']))
        for record in db.execute("SELECT staged_parts FROM scan WHERE task_id=? AND state NOT IN ('done','unstable')", (task['id'],)):
            references.update(p['group'] for p in json.loads(record['staged_parts']))
    for group in core.rows("SELECT * FROM groups WHERE task_id=? AND status IN ('committed','cancelled')", (task['id'],)):
        if group['id'] in references:
            continue
        try:
            if group['cloud_dest']:
                cloud.delete_owned_group(group['cloud_dest'], task['cloud_dest'] or core.one('SELECT cloud_dest FROM tasks WHERE id=?', (task['id'],))['cloud_dest'])
            core.execute("UPDATE groups SET status='retired' WHERE id=?", (group['id'],))
            core.log(task['id'], '已清理完全失去有效引用的旧数据组', run_id=task['run_id'])
        except Exception:
            core.log(task['id'], '无用组清理暂未完成，将在后续运行重试', 'warning', task['run_id'])


def one_group(task: dict):
    task_id = task['id']
    core.set_status(task_id, 'running')
    group = core.one("SELECT * FROM groups WHERE task_id=? AND status NOT IN ('committed','empty','retired','cancelled') ORDER BY created LIMIT 1", (task_id,))
    if not group:
        archive.prepare_candidates(task, lambda: not allow_poll(task_id))
        if not allowed(task_id):
            return
        pending = core.one("SELECT COUNT(*) n FROM scan WHERE task_id=? AND state='pending' AND kind IN ('new','modified')", (task_id,))['n']
        if not pending:
            finish(task)
            return
        group = archive.create_group(task)
    core.set_status(task_id, 'running')
    while not STOP.is_set():
        if not allowed(task_id):
            # Already-started uploads finish; no new pack or transfer is started.
            pump_uploads(task_id, group['id'], start=False)
            core.set_status(task_id, 'paused' if core.one('SELECT paused FROM tasks WHERE id=?', (task_id,))['paused'] else 'waiting_window')
            return
        pump_uploads(task_id, group['id'])
        failed = core.one("SELECT COUNT(*) n FROM objects WHERE group_id=? AND status='failed'", (group['id'],))['n']
        if failed:
            raise CloudError('文件上传重试耗尽，请检查 CloudDrive2、账号状态或网络后重试')
        group = core.one('SELECT * FROM groups WHERE id=?', (group['id'],))
        if group['status'] == 'building':
            archive.prepare_candidates(task, lambda: not allow_poll(task_id))
            if not allowed(task_id):
                continue
            if archive.build_pack(task, group):
                pump_uploads(task_id, group['id'])
                continue
            # A batch may contain more un-hashed candidates than the preparation limit.
            unhashed = core.one("SELECT COUNT(*) n FROM scan WHERE task_id=? AND state='pending' AND sha256 IS NULL", (task_id,))['n']
            packs = core.one("SELECT COUNT(DISTINCT pack) n FROM members WHERE group_id=?", (group['id'],))['n']
            if unhashed and packs < core.GROUP_PACKS:
                continue
            archive.close_group(task, group)
            group = core.one('SELECT * FROM groups WHERE id=?', (group['id'],))
            if group['status'] == 'empty':
                return
            continue
        pending = core.one("SELECT COUNT(*) n FROM objects WHERE group_id=? AND status!='uploaded'", (group['id'],))['n']
        if pending:
            core.progress(task_id, 'upload', percent=None)
            STOP.wait(1)
            continue
        if not core.one("SELECT id FROM objects WHERE group_id=? AND kind='commit'", (group['id'],)):
            path = Path(group['directory']) / 'commit.json'
            objects = core.rows('SELECT name,size,sha256 FROM objects WHERE group_id=? ORDER BY name', (group['id'],))
            path.write_text(json.dumps({'format': 1, 'group_id': group['id'], 'objects': objects}), encoding='utf-8')
            core.execute('INSERT INTO objects(id,group_id,name,size,sha256,kind) VALUES (?,?,?,?,?,?)',
                         (core.identifier(), group['id'], path.name, path.stat().st_size, core.digest_file(path), 'commit'))
            continue
        commit_group(task, group)
        # Yield at group boundaries so other tasks can make progress.
        core.set_status(task_id, 'queued')
        return


def start_run(task: dict):
    run_id = core.identifier()
    core.execute('INSERT INTO runs(id,task_id,started,status) VALUES (?,?,?,?)', (run_id, task['id'], core.now(), 'running'))
    core.execute('UPDATE tasks SET run_id=?,initialized=1 WHERE id=?', (run_id, task['id']))
    task['run_id'] = run_id
    ensure_run_scan(task)
    core.set_status(task['id'], 'queued')


def ensure_run_scan(task: dict):
    progress = json.loads(core.one('SELECT progress FROM tasks WHERE id=?', (task['id'],))['progress'])
    if progress.get('scan_run_id') == task['run_id']:
        return
    run = core.one('SELECT started FROM runs WHERE id=?', (task['run_id'],))
    if 'scan_run_id' not in progress and run and (task['last_scan'] or 0) >= run['started']:
        # Preserve in-progress fragments when upgrading a run from 0.2.0.
        core.progress(task['id'], progress.get('stage', 'hash'), scan_run_id=task['run_id'])
        return
    reuse = (task['manual'] and progress.get('reuse_scan_id') == task['scan_id']
             and task['scan_id'] and (task['last_scan'] or 0) >= core.now() - 300)
    if reuse:
        core.log(task['id'], '复用5分钟内刚完成的扫描；读取和打包时仍检查源文件是否变化', run_id=task['run_id'])
    else:
        core.log(task['id'], '开始备份前扫描：清单已过期或本次为新的自动运行', run_id=task['run_id'])
        scan_task(task, lambda: STOP.is_set() or bool(core.one('SELECT paused FROM tasks WHERE id=?', (task['id'],))['paused']))
    core.progress(task['id'], 'hash', percent=None, phase_bytes=0, phase_total=0,
                  scan_run_id=task['run_id'], reuse_scan_id=None,
                  catalog_dirty=any(k != 'unchanged' and v for k, v in summary(task['id']).items()))


def next_due(task: dict) -> float | None:
    completed = task.get('last_completed') or task.get('last_success')
    return completed + task['interval_days'] * 86400 if completed else None


def schedule():
    inside, key = window()
    if not inside or not core.settings()['auto_schedule']:
        return
    for task in core.rows("SELECT * FROM tasks WHERE auto=1 AND initialized=1 AND operation IS NULL AND paused=0 AND status IN ('complete','attention')"):
        due = next_due(task)
        if due is not None and core.now() >= due:
            core.execute("UPDATE tasks SET operation='backup',status='queued',manual=0,run_id=NULL,last_window=?,updated=? WHERE id=?", (key, core.now(), task['id']))


def loop():
    global ACTIVE_TASK
    for group in core.rows("SELECT task_id,id,directory FROM groups WHERE status='committed'"):
        for path,parent in ((Path(group['directory']),core.OUT), (core.WORK/group['task_id']/group['id'],core.WORK)):
            if path.exists():
                core.owned_remove(path,parent)
    core.execute("UPDATE objects SET status='ready' WHERE status='uploading'")
    core.execute("UPDATE tasks SET status='queued' WHERE operation IS NOT NULL AND paused=0 AND status NOT IN ('error','scan_ready')")
    while not STOP.is_set():
        try:
            recover_publications()
            with CONTROL_LOCK:
                settle_cancellations()
                settle_pauses()
            for waiting in core.rows("SELECT id FROM tasks WHERE status='space_wait' AND paused=0"):
                try:
                    archive.reserve_group()
                    core.set_status(waiting['id'], 'queued')
                except archive.Wait:
                    pass
            schedule()
            with CONTROL_LOCK:
                tasks = core.rows("SELECT * FROM tasks WHERE operation IS NOT NULL AND paused=0 AND status NOT IN ('error','scan_ready','space_wait') ORDER BY updated")
                selected = next((t for t in tasks if t['operation'] == 'scan' or allowed(t['id'])), None)
                ACTIVE_TASK = selected['id'] if selected else None
            if not selected:
                WAKE.wait(2)
                WAKE.clear()
                continue
            task = selected
            try:
                if task['operation'] == 'scan':
                    scan_task(task, lambda: STOP.is_set() or bool(core.one('SELECT paused FROM tasks WHERE id=?', (task['id'],))['paused']))
                    core.execute("UPDATE tasks SET status='scan_ready',operation=NULL WHERE id=?", (task['id'],))
                else:
                    if not task['run_id']:
                        start_run(task)
                        task = core.one('SELECT * FROM tasks WHERE id=?', (task['id'],))
                    else:
                        ensure_run_scan(task)
                    one_group(task)
            except Interrupted:
                core.set_status(task['id'], 'paused' if not STOP.is_set() else 'queued')
            except archive.Wait as error:
                core.set_status(task['id'], 'space_wait', str(error))
            except Exception as error:
                core.set_status(task['id'], 'error', str(error))
                if task.get('run_id'):
                    core.execute("UPDATE runs SET status='error',error=? WHERE id=?", (core.redact(error), task['run_id']))
                core.log(task['id'], '需要处理：' + core.redact(error), 'error', task.get('run_id'))
                notify_terminal(task, core.redact(error))
            finally:
                with CONTROL_LOCK:
                    ACTIVE_TASK = None
                    settle_pauses()
        except Exception as error:
            # No raw exceptions: upstream errors may carry credential-bearing URLs.
            print('worker:', core.redact(error), flush=True)
            STOP.wait(3)


def start():
    STOP.clear()
    threading.Thread(target=loop, daemon=True, name='backup-worker').start()


def stop():
    STOP.set()
    WAKE.set()
