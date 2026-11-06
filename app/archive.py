from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

from . import core
from .scan import compression, hash_candidate


class Wait(RuntimeError):
    pass


class SourceChanged(RuntimeError):
    pass


def password(task_id: str | None = None) -> str:
    values = core.get_secrets()
    value = values.get('task_password:' + task_id, '') if task_id else ''
    value = value or values.get('archive_password', '')
    if not value:
        raise RuntimeError('请先设置归档密码')
    return value


def tool(command: list[str], task_id: str, stage: str, cwd=None):
    started=time.monotonic()
    core.set_status(task_id, 'running')
    core.progress(task_id, stage, percent=0, phase_bytes=0, phase_total=0,
                  stage_started=core.now())
    if os.name == 'posix' and shutil.which('nice'):
        command = ['nice', '-n', '10', *command]
    proc = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, env={**os.environ, 'LC_ALL': 'C.UTF-8'},
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    tail = bytearray()
    last = 0.0
    assert proc.stdout
    for data in iter(lambda: proc.stdout.read(1), b''):
        tail.extend(data)
        if len(tail) > 12000:
            del tail[:-12000]
        matches = re.findall(rb'(\d{1,3}(?:\.\d+)?)%', tail[-12:]) if data == b'%' else []
        if matches and time.monotonic() - last > 0.4:
            core.progress(task_id, stage, percent=min(100, float(matches[-1])))
            last = time.monotonic()
    result = proc.wait()
    if result:
        raise RuntimeError(Path(command[0]).name + ' 执行失败：' + core.redact(tail.decode('utf-8', errors='replace')))
    core.progress(task_id, stage, percent=100)
    label={'pack':'压缩加密','local_verify':'本地归档校验','parity':'冗余生成','parity_verify':'冗余校验','index':'索引处理'}.get(stage,stage)
    core.log(task_id,f'{label}完成，耗时 {time.monotonic()-started:.1f} 秒')


def seven(verb: str, archive: Path, task_id: str, extra=(), cwd=None, stage='pack'):
    core.progress(task_id, stage, current_path=archive.name)
    tool([os.getenv('NCB_7ZZ', '7zz'), verb, '-y', '-bb0', '-bsp1', '-p' + password(task_id),
          str(archive), *extra], task_id, stage, cwd)


def reserve_group():
    needed = min(core.MAX_UPLOAD * (core.GROUP_PACKS + 2), 30_000_000_000)
    used = core.disk_used()
    quota = int(core.settings()['quota_gb']) * 1_000_000_000
    free = shutil.disk_usage(core.WORK).free
    headroom = min(10_000_000_000, max(256 * 1024**2, quota // 20))
    if used + needed > quota or free < needed + headroom:
        raise Wait('暂存配额或磁盘余量不足，等待释放空间')


def space_check(extra=0):
    quota = int(core.settings()['quota_gb']) * 1_000_000_000
    if core.disk_used() + extra > quota:
        raise Wait('已达到临时空间配额')


def group_directory(group: dict) -> Path:
    return core.OUT / group['task_id'] / group['id']


def create_group(task: dict) -> dict:
    reserve_group()
    group_id = core.identifier()
    directory = core.OUT / task['id'] / group_id
    directory.mkdir(parents=True)
    core.execute('INSERT INTO groups(id,task_id,run_id,status,directory,created) VALUES (?,?,?,?,?,?)',
                 (group_id, task['id'], task['run_id'], 'building', str(directory), core.now()))
    return core.one('SELECT * FROM groups WHERE id=?', (group_id,))


def _record_file(db, task_id: str, item: dict, parts: list):
    core.journal_file(db, task_id, item['path'])
    old = db.execute('SELECT text_content FROM files WHERE task_id=? AND path=?', (task_id, item['path'])).fetchone()
    old_bytes = len((old['text_content'] or '').encode()) if old else 0
    value = item.get('text_content')
    used = int(json.loads(db.execute("SELECT value FROM settings WHERE key='text_cache_bytes'").fetchone()['value']))
    new_bytes = len((value or '').encode())
    if used - old_bytes + new_bytes > 128 * 1024**2:
        value, new_bytes = None, 0
    db.execute("UPDATE settings SET value=? WHERE key='text_cache_bytes'", (str(max(0, used - old_bytes + new_bytes)),))
    db.execute('''INSERT OR REPLACE INTO files(task_id,path,root,relative,size,mtime_ns,ctime_ns,sha256,parts,present,backed_up,text_content)
      VALUES (?,?,?,?,?,?,?,?,?,1,?,?)''', (task_id, item['path'], item['root'], item['relative'], item['size'],
      item['mtime_ns'], item['ctime_ns'], item['sha256'], json.dumps(parts), core.now(), value))


def resolve_reuse(task: dict, item: dict) -> bool:
    current = core.one('SELECT * FROM files WHERE task_id=? AND path=?', (task['id'], item['path']))
    existing = current if current and current['cloud_state'] == 'ok' and current['sha256'] == item['sha256'] else core.one(
        "SELECT * FROM files WHERE task_id=? AND sha256=? AND cloud_state='ok' LIMIT 1", (task['id'], item['sha256']))
    if not existing:
        return False
    deleted = core.one("SELECT * FROM scan WHERE task_id=? AND path=? AND kind='deleted'", (task['id'], existing['path']))
    with core.connect() as db:
        _record_file(db, task['id'], item, json.loads(existing['parts']))
        if deleted and existing['path'] != item['path']:
            core.journal_file(db, task['id'], existing['path'])
            db.execute('DELETE FROM files WHERE task_id=? AND path=?', (task['id'], existing['path']))
            cached = int(json.loads(db.execute("SELECT value FROM settings WHERE key='text_cache_bytes'").fetchone()['value']))
            db.execute("UPDATE settings SET value=? WHERE key='text_cache_bytes'", (str(max(0, cached - len((existing.get('text_content') or '').encode()))),))
            db.execute("UPDATE scan SET state='done',kind='moved_from' WHERE task_id=? AND path=?", (task['id'], existing['path']))
        kind = 'moved' if deleted and existing['path'] != item['path'] else 'metadata' if current else 'reused'
        db.execute("UPDATE scan SET state='done',kind=?,text_content=NULL WHERE task_id=? AND path=?", (kind, task['id'], item['path']))
    core.progress(task['id'], 'hash', catalog_dirty=True)
    return True


def prepare_candidates(task: dict, stopped=lambda: False):
    # Hash only files whose metadata changed. Hash reads are streaming, not staged copies.
    candidates = core.rows("SELECT * FROM scan WHERE task_id=? AND state='pending' AND sha256 IS NULL AND kind IN ('new','modified') ORDER BY path LIMIT ?", (task['id'], core.PACK_FILES))
    if candidates:
        core.progress(task['id'], 'hash', percent=0, phase_bytes=0,
                      phase_total=candidates[0]['size'], current_path=candidates[0]['path'])
    hashed_bytes = 0
    batch = []
    last_hashed = None
    def flush():
        if not batch:
            return
        items=batch[:]
        batch.clear()
        with core.connect() as db:
            db.executemany('UPDATE scan SET sha256=?,text_content=? WHERE task_id=? AND path=?',
                [(i['sha256'],i.get('text_content'),task['id'],i['path']) for i in items])
        for item in items:
            try:
                resolve_reuse(task,item)
            finally:
                item.pop('text_content',None)
    try:
        for item in candidates:
            if stopped():
                return
            try:
                hash_candidate(item,task['id'],stopped,persist=False)
                last_hashed = item
                batch.append(item)
                hashed_bytes+=item['size']
                if len(batch)>=32 or hashed_bytes>=core.PACK_PAYLOAD:
                    flush()
                if hashed_bytes>=core.PACK_PAYLOAD:
                    return
            except Exception as error:
                from .scan import Interrupted
                if isinstance(error,Interrupted):
                    return
                core.execute("UPDATE scan SET state='unstable',error=? WHERE task_id=? AND path=?",(core.redact(error),task['id'],item['path']))
                core.log(task['id'],'文件暂未处理：'+item['path']+'；'+core.redact(error),'warning',task['run_id'])
    finally:
        flush()
        if last_hashed and not stopped():
            core.progress(task['id'], 'hash', percent=100, phase_bytes=last_hashed['size'],
                          phase_total=last_hashed['size'], current_path=last_hashed['path'])


def build_pack(task: dict, group: dict) -> bool:
    task_id = task['id']
    directory = group_directory(group)
    existing = core.rows("SELECT * FROM objects WHERE group_id=? AND kind='data'", (group['id'],))
    logical = sorted({r['name'].split('.7z')[0] for r in existing})
    number = len(logical) + 1
    if number > core.GROUP_PACKS:
        return False
    candidates = core.rows("""SELECT task_id,path,root,relative,size,mtime_ns,ctime_ns,kind,state,sha256,offset,staged_parts
      FROM scan WHERE task_id=? AND state='pending' AND sha256 IS NOT NULL
      AND kind IN ('new','modified') ORDER BY path LIMIT ?""", (task_id, core.PACK_FILES))
    if not candidates:
        return False
    level = compression(candidates[0]['path'])
    pack_name = 'pack-%03d-L%d.7z' % (number, level)
    stage = core.WORK / task_id / group['id'] / ('stage-%03d' % number)
    if stage.exists():
        core.owned_remove(stage, core.WORK)
    stage.mkdir(parents=True)
    # Orphan output from a crash before the DB transaction is safe to recreate.
    for orphan in directory.glob(pack_name + '*'):
        core.owned_remove(orphan, core.OUT)
    members = []
    total = 0
    planned = min(core.PACK_PAYLOAD,sum(min(max(0,i['size']-i['offset']),core.PACK_PAYLOAD) for i in candidates if compression(i['path'])==level))
    space_check(planned*2+4*1024**2)
    core.progress(task_id, 'stage', percent=0, phase_bytes=0, phase_total=planned,
                  pack_number=number, group_id=group['id'])
    last_progress = 0.0
    for item in candidates:
        if compression(item['path']) != level:
            continue
        if members and (total >= core.PACK_PAYLOAD or len(members) >= core.PACK_FILES):
            break
        size = min(item['size'] - item['offset'], core.PACK_PAYLOAD - total)
        if size < 0:
            raise RuntimeError('分段偏移无效')
        if members and size == 0 and item['size']:
            break
        expected = (item['size'], item['mtime_ns'], item['ctime_ns'])
        source = Path(item['path'])
        try:
            if core.signature(source) != expected:
                raise SourceChanged('源文件已变化')
            is_fragment = item['size'] > core.PACK_PAYLOAD
            root_id = hashlib.sha256(item['root'].encode()).hexdigest()[:8]
            path_id = hashlib.sha256(item['path'].encode()).hexdigest()[:16]
            entry = ('fragments/' + path_id + '/%020d.bin' % item['offset']) if is_fragment else ('roots/' + root_id + '/' + item['relative'])
            if '\n' in entry or '\r' in entry:
                raise RuntimeError('文件名包含换行，无法安全归档')
            dest = stage / entry
            dest.parent.mkdir(parents=True, exist_ok=True)
            h = hashlib.sha256()
            remaining = size
            with source.open('rb') as src, dest.open('wb') as dst:
                src.seek(item['offset'])
                while remaining:
                    chunk = src.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise SourceChanged('源文件被截断')
                    dst.write(chunk)
                    h.update(chunk)
                    remaining -= len(chunk)
                    if time.monotonic() - last_progress > 0.5:
                        core.progress(task_id, 'stage', current_path=item['path'],
                                      phase_bytes=total + size - remaining, phase_total=planned,
                                      percent=100 * (total + size - remaining) / max(planned, 1))
                        last_progress = time.monotonic()
            if core.signature(source) != expected:
                raise SourceChanged('源文件在复制期间变化')
            # Never inherit DSM ACL xattrs into private staging.
            dest.chmod(0o600)
            os.utime(dest, ns=(item['mtime_ns'], item['mtime_ns']))
            final = item['offset'] + size >= item['size']
            members.append({'path': item['path'], 'entry': entry, 'offset': item['offset'],
                            'length': size, 'sha256': h.hexdigest(), 'final': final})
            total += size
        except (OSError, SourceChanged, RuntimeError) as error:
            core.execute("UPDATE scan SET state='unstable',error=? WHERE task_id=? AND path=?", (core.redact(error), task_id, item['path']))
            core.log(task_id, '文件暂未处理：' + item['path'], 'warning', task['run_id'])
    if not members:
        core.owned_remove(stage, core.WORK)
        return False
    listing = stage.parent / ('pack-%03d.lst' % number)
    listing.write_text('\n'.join(m['entry'] for m in members) + '\n', encoding='utf-8')
    core.progress(task_id, 'stage', percent=100, phase_bytes=total, phase_total=total,
                  current_path=members[-1]['path'])
    archive = directory / pack_name
    core.progress(task_id, 'pack', current_path=pack_name, percent=0, pack_number=number)
    dictionary = ['-md=8m' if level>=3 else '-md=1m'] if level else []
    seven('a', archive, task_id, ['-t7z', '-mhe=on', '-ms=off', '-mmt=1', '-mx=%d' % level,*dictionary,
          '-scsUTF-8', '-spd', '-v%db' % core.MAX_UPLOAD, '@' + str(listing)], cwd=stage)
    volumes = sorted(directory.glob(pack_name + '.*'))
    if len(volumes) == 1:
        os.replace(volumes[0], archive)
        volumes = [archive]
    seven('t', volumes[0], task_id, stage='local_verify')
    if any(v.stat().st_size > core.MAX_UPLOAD for v in volumes):
        raise RuntimeError('压缩包超过3900MB限制')
    core.sync_files(volumes)
    object_rows = [(core.identifier(), group['id'], v.name, v.stat().st_size, core.digest_file(v), 'data') for v in volumes]
    with core.connect() as db:
        db.executemany('INSERT INTO objects(id,group_id,name,size,sha256,kind) VALUES (?,?,?,?,?,?)', object_rows)
        for member in members:
            db.execute('INSERT INTO members VALUES (?,?,?,?,?,?,?,?)',
                       (group['id'], pack_name, member['path'], member['entry'], member['offset'], member['length'], member['sha256'], int(member['final'])))
            db.execute('UPDATE scan SET offset=?,state=? WHERE task_id=? AND path=?',
                       (member['offset'] + member['length'], 'packed' if member['final'] else 'pending', task_id, member['path']))
    core.owned_remove(stage, core.WORK)
    listing.unlink(missing_ok=True)
    core.log(task_id, f'已封包 {pack_name}：{len(members)} 项，{total} 字节', run_id=task['run_id'])
    return True


def _json_archive(data: dict, archive: Path, task_id: str, name: str) -> list[Path]:
    stage = core.WORK / task_id / ('meta-' + core.identifier())
    stage.mkdir(parents=True)
    try:
        (stage / name).write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
        seven('a', archive, task_id, ['-t7z', '-mhe=on', '-mx=3', '-mmt=1', '-v%db' % core.MAX_UPLOAD, name], cwd=stage, stage='index')
        volumes = sorted(archive.parent.glob(archive.name + '.*'))
        if len(volumes) == 1:
            os.replace(volumes[0], archive)
            volumes = [archive]
        seven('t', volumes[0], task_id, stage='local_verify')
        return volumes
    finally:
        core.owned_remove(stage, core.WORK)


def parity_layout(total,largest):
    block=max(4096,math.ceil(total/256/4)*4)
    count=math.ceil(largest/block)+2
    volumes=min(count,31,max(2,math.ceil(block*count/max(core.MAX_UPLOAD-1024**2,1))))
    return block,count,volumes


def close_group(task: dict, group: dict):
    directory = group_directory(group)
    objects = core.rows("SELECT * FROM objects WHERE group_id=? AND kind='data'", (group['id'],))
    if not objects:
        core.execute("UPDATE groups SET status='empty' WHERE id=?", (group['id'],))
        return
    metadata = {'format': 1, 'task_id': task['id'], 'group_id': group['id'],
                'roots': json.loads(task['roots']), 'members': core.rows('SELECT * FROM members WHERE group_id=?', (group['id'],)),
                'objects': [{k: o[k] for k in ('name', 'size', 'sha256')} for o in objects]}
    manifest = directory / 'group-manifest.7z'
    for orphan in directory.glob('group-manifest*'):
        core.owned_remove(orphan, core.OUT)
    for orphan in directory.glob('recovery*.par2'):
        core.owned_remove(orphan, core.OUT)
    extra = _json_archive(metadata, manifest, task['id'], 'group-manifest.json')
    protected = [directory / o['name'] for o in objects] + extra
    total = sum(p.stat().st_size for p in protected)
    largest = max(p.stat().st_size for p in protected)
    block,count,volumes = parity_layout(total,largest)
    space_check(block * count + 4 * 1024**2)
    core.progress(task['id'], 'parity', percent=0, current_path='生成完整文件丢失保护')
    core.log(task['id'],f'冗余计划：块大小 {block / 1_000_000:.1f} MB，恢复块 {count}，内存预算96MiB，单线程',run_id=task['run_id'])
    tool([os.getenv('NCB_PAR2', 'par2'), 'create', '-t1', '-m96', '-s%d' % block,
          '-c%d' % count, '-u', '-n%d' % volumes, str(directory / 'recovery.par2'),
          *[str(p) for p in protected]], task['id'], 'parity', cwd=directory)
    tool([os.getenv('NCB_PAR2', 'par2'), 'verify', '-q', '-t1', '-m96', str(directory / 'recovery.par2')], task['id'], 'parity_verify', cwd=directory)
    outputs = extra + sorted(directory.glob('recovery*.par2'))
    if any(p.stat().st_size > core.MAX_UPLOAD for p in outputs):
        raise RuntimeError('冗余文件超过3900MB限制')
    core.sync_files(outputs)
    with core.connect() as db:
        db.execute("DELETE FROM objects WHERE group_id=? AND kind!='data'", (group['id'],))
        for path in outputs:
            db.execute('INSERT INTO objects(id,group_id,name,size,sha256,kind) VALUES (?,?,?,?,?,?)',
                       (core.identifier(), group['id'], path.name, path.stat().st_size, core.digest_file(path), 'metadata' if path in extra else 'parity'))
        db.execute("UPDATE groups SET status='uploading' WHERE id=?", (group['id'],))
    core.log(task['id'], '恢复组已封口，冗余覆盖组内任意一个缺失数据对象', run_id=task['run_id'])
