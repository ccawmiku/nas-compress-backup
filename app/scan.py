from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import time
from pathlib import Path

from . import core

IGNORE_DIRS = {'@eaDir', '#recycle', '.snapshot', '@tmp', '.git'}
IGNORE_SUFFIXES = {'.tmp', '.part', '.crdownload', '.download'}
STORE = set('mp4 mkv mov avi webm m4v mp3 aac m4a flac ogg opus jpg jpeg png webp gif avif heic zip 7z rar gz bz2 xz zst pdf docx xlsx pptx'.split())
NORMAL = set('txt csv tsv log json jsonl xml html css js ts tsx jsx py sh sql md xmp db sqlite sqlite3 yaml yml toml ini conf'.split())
TEXT = NORMAL - {'db', 'sqlite', 'sqlite3'}


def compression(path: str) -> int:
    ext = Path(path).suffix.lower().lstrip('.')
    return 0 if ext in STORE else 5 if ext in NORMAL else 1


def excluded(path: Path, root: Path, patterns: list[str]) -> bool:
    if path.is_symlink() or path.name in IGNORE_DIRS or path.suffix.lower() in IGNORE_SUFFIXES:
        return True
    absolute = str(path.resolve())
    for directory in (core.HOST_DATA, core.HOST_WORK, core.HOST_OUT):
        if absolute == directory or absolute.startswith(directory.rstrip('/') + '/'):
            return True
    relative = path.relative_to(root).as_posix()
    return any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in patterns)


class Interrupted(RuntimeError):
    pass


def scan_task(task: dict, stopped=lambda: False) -> dict:
    task_id = task['id']
    roots = [core.permitted(p) for p in json.loads(task['roots'])]
    patterns = json.loads(task['excludes'])
    for root in roots:
        if not root.is_dir():
            raise RuntimeError('来源目录不存在或未挂载：' + str(root))
    scan_id = core.identifier()
    core.set_status(task_id, 'scanning')
    core.progress(task_id, 'scan', scan_count=0, scan_bytes=0, percent=None,
                  current_path='', changed_files=0, processed_files=0, processed_bytes=0)
    # Build a disposable staging table in short transactions. The last good scan is
    # replaced only after a complete walk, while pause/settings writes remain usable.
    count = size = 0
    last = 0.0
    table = 'scan_stage_' + core.identifier()
    try:
        with core.connect() as db:
            db.execute(f'CREATE TABLE {table} AS SELECT * FROM scan WHERE 0')
            db.execute(f'CREATE UNIQUE INDEX {table}_path ON {table}(path)')
            db.commit()
            for root in roots:
                def onerror(error):
                    raise RuntimeError('目录无法读取：' + str(error.filename))
                for directory, dirs, files in os.walk(root, onerror=onerror, followlinks=False):
                    if stopped():
                        raise Interrupted('扫描已暂停')
                    parent = Path(directory)
                    dirs[:] = sorted(d for d in dirs if not excluded(parent / d, root, patterns))
                    for name in sorted(files):
                        path = parent / name
                        if excluded(path, root, patterns) or not path.is_file():
                            continue
                        value = str(path)
                        stat = path.stat()
                        old = db.execute('SELECT * FROM files WHERE task_id=? AND path=?', (task_id, value)).fetchone()
                        kind = 'new' if old is None else ('unchanged' if old['present'] and (old['size'], old['mtime_ns'], old['ctime_ns']) ==
                                (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns) else 'modified')
                        state = 'done' if kind == 'unchanged' else 'pending'
                        cursor = db.execute(f'''INSERT OR IGNORE INTO {table}(task_id,path,root,relative,size,mtime_ns,ctime_ns,kind,state,offset,staged_parts)
                          VALUES (?,?,?,?,?,?,?,?,?,0,'[]')''', (task_id, value, str(root), path.relative_to(root).as_posix(),
                          stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, kind, state))
                        if not cursor.rowcount:
                            continue
                        count += 1
                        size += stat.st_size
                        if count % 200 == 0:
                            db.commit()
                        if time.monotonic() - last > 0.6:
                            LIVE[task_id] = {'stage': 'scan', 'scan_count': count, 'scan_bytes': size,
                                             'current_path': str(parent), 'percent': None, 'heartbeat': core.now()}
                            last = time.monotonic()
            db.execute('DELETE FROM scan WHERE task_id=?', (task_id,))
            db.execute(f'INSERT INTO scan SELECT * FROM {table}')
            db.execute('''INSERT INTO scan(task_id,path,root,relative,size,mtime_ns,ctime_ns,kind,state,sha256)
              SELECT task_id,path,root,relative,size,mtime_ns,ctime_ns,'deleted','pending',sha256 FROM files
              WHERE task_id=? AND present=1 AND path NOT IN (SELECT path FROM scan WHERE task_id=?)''', (task_id, task_id))
            summary = {r['kind']: r['n'] for r in db.execute('SELECT kind,COUNT(*) n FROM scan WHERE task_id=? GROUP BY kind', (task_id,))}
            db.execute(f'DROP TABLE {table}')
    finally:
        LIVE.pop(task_id, None)
        with core.connect() as db:
            db.execute(f'DROP TABLE IF EXISTS {table}')
    core.execute('UPDATE tasks SET last_scan=?,scan_id=? WHERE id=?', (core.now(), scan_id, task_id))
    core.progress(task_id, 'scan_complete', scan_count=count, scan_bytes=size, percent=100,
                  changed_files=sum(v for k, v in summary.items() if k != 'unchanged'),
                  total_source_bytes=core.one("SELECT COALESCE(SUM(size),0) n FROM scan WHERE task_id=? AND kind IN ('new','modified')", (task_id,))['n'])
    core.log(task_id, f'扫描完成：{count} 个文件，新增 {summary.get("new",0)}，修改 {summary.get("modified",0)}，源已删除 {summary.get("deleted",0)}')
    return summary


LIVE: dict[str, dict] = {}


def hash_candidate(item: dict, task_id: str, stopped=lambda: False) -> dict:
    path = Path(item['path'])
    expected = (item['size'], item['mtime_ns'], item['ctime_ns'])
    if core.signature(path) != expected:
        raise RuntimeError('源文件在扫描后发生变化，等待下次扫描')
    h = hashlib.sha256()
    read = 0
    text = bytearray()
    cache_text = path.suffix.lower().lstrip('.') in TEXT and item['size'] <= core.TEXT_LIMIT
    last = 0.0
    with path.open('rb') as src:
        for block in iter(lambda: src.read(1024 * 1024), b''):
            if stopped():
                raise Interrupted('等待继续读取文件')
            h.update(block)
            read += len(block)
            if cache_text:
                text.extend(block)
            if time.monotonic() - last > 0.6:
                core.progress(task_id, 'hash', current_path=str(path), phase_bytes=read,
                              phase_total=item['size'], percent=100 * read / max(item['size'], 1))
                last = time.monotonic()
    if core.signature(path) != expected:
        raise RuntimeError('源文件在读取时发生变化，等待下次扫描')
    value = None
    if cache_text:
        try:
            value = bytes(text).decode('utf-8-sig')
            if '\x00' in value:
                value = None
        except UnicodeDecodeError:
            pass
    core.execute('UPDATE scan SET sha256=?,text_content=? WHERE task_id=? AND path=?',
                 (h.hexdigest(), value, task_id, str(path)))
    item.update(sha256=h.hexdigest(), text_content=value)
    return item
