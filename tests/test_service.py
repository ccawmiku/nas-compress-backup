import json
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from app import core, worker
from app.main import app
from app.scan import scan_task, Interrupted
from conftest import make_task


def test_admin_secrets_and_same_origin(state):
    with TestClient(app) as client:
        assert client.get('/api/overview').status_code == 401
        response = client.post('/api/auth/setup', json={'password': 'testing-password'})
        assert response.status_code == 200
        assert 'HttpOnly' in response.headers['set-cookie']
        assert client.post('/api/auth/setup', json={'username': 'second', 'password': 'testing-password'}).status_code == 409
        settings = client.get('/api/settings').json()
        serialized = json.dumps(settings)
        assert 'fixture-token-only' not in serialized
        assert 'fixture-password-only' not in serialized
        assert settings['has_archive_password']
        assert client.put('/api/settings', json={'quota_gb': 128}, headers={'origin': 'http://different-host'}).status_code == 403
        assert client.put('/api/settings', json={'quota_gb': 128}).status_code == 200
        assert core.settings()['quota_gb'] == 128
        assert client.post('/api/auth/logout').status_code == 200
        assert client.get('/api/tasks/not-real').status_code == 401
        assert client.post('/api/auth/login', json={'password': 'wrong-password'}).status_code == 401
        # Existing username values are irrelevant after migration; retain the password.
        core.execute("UPDATE admin SET username='old-user-name'")
        assert client.post('/api/auth/login', json={'password': 'testing-password'}).status_code == 200
        assert 'username' not in client.get('/api/auth/status').json()


def test_independent_task_intervals_and_night_window(state, monkeypatch):
    stamp = 2000000000
    monkeypatch.setattr(core, 'now', lambda: stamp)
    monkeypatch.setattr(worker, 'window', lambda: (True, 'night'))
    first, second = make_task(state, None), make_task(state, None)
    for task, days in ((first, 2), (second, 7)):
        core.execute("UPDATE tasks SET initialized=1,status='complete',interval_days=?,last_completed=? WHERE id=?",
                     (days, stamp - 3 * 86400, task['id']))
    worker.schedule()
    assert core.one('SELECT operation FROM tasks WHERE id=?', (first['id'],))['operation'] == 'backup'
    assert core.one('SELECT operation FROM tasks WHERE id=?', (second['id'],))['operation'] is None
    core.execute('UPDATE tasks SET last_completed=? WHERE id=?', (stamp - 8 * 86400, second['id']))
    monkeypatch.setattr(worker, 'window', lambda: (False, ''))
    worker.schedule()
    assert core.one('SELECT operation FROM tasks WHERE id=?', (second['id'],))['operation'] is None
    # Manual scans do not move the next due date; a completed manual backup does.
    record = core.one('SELECT * FROM tasks WHERE id=?', (second['id'],))
    assert worker.next_due(record) == stamp - 86400


def test_interval_edit_keeps_completed_task_schedulable(state):
    task = make_task(state, None)
    core.execute("UPDATE tasks SET status='complete',initialized=1,last_completed=1000 WHERE id=?", (task['id'],))
    with TestClient(app) as client:
        client.post('/api/auth/setup', json={'password': 'testing-password'})
        body = {'name': task['name'], 'roots': [str(state)], 'interval_days': 3}
        assert client.patch('/api/tasks/' + task['id'], json=body).status_code == 200
        current = client.get('/api/tasks/' + task['id']).json()
        assert current['status'] == 'complete' and current['next_run_at'] == 1000 + 3 * 86400
        for invalid in (0, -1, 1.5, True, 3651, '3'):
            body['interval_days'] = invalid
            assert client.patch('/api/tasks/' + task['id'], json=body).status_code == 400


def test_legacy_schema_migrates_schedule_and_keeps_password(state):
    task = make_task(state, None)
    core.execute('UPDATE tasks SET last_success=1000 WHERE id=?', (task['id'],))
    with core.connect() as db:
        db.execute('ALTER TABLE tasks DROP COLUMN interval_days')
        db.execute('ALTER TABLE tasks DROP COLUMN last_completed')
    core.init()
    current = core.one('SELECT * FROM tasks WHERE id=?', (task['id'],))
    assert current['interval_days'] == 7 and current['last_completed'] == 1000


def test_run_reuses_recent_reviewed_scan_once_and_clears_old_progress(state, monkeypatch):
    task = make_task(state, None)
    (state / 'file.txt').write_text('fixture', encoding='utf-8')
    scan_task(task)
    core.execute("UPDATE tasks SET status='scan_ready' WHERE id=?", (task['id'],))
    with TestClient(app) as client:
        client.post('/api/auth/setup', json={'password': 'testing-password'})
        assert client.post(f"/api/tasks/{task['id']}/run").status_code == 200
    current = core.one('SELECT * FROM tasks WHERE id=?', (task['id'],))
    assert json.loads(current['progress'])['stage'] == 'queued'
    assert json.loads(current['progress'])['percent'] is None
    def unexpected_scan(*args, **kwargs):
        raise AssertionError('Recent reviewed scan must not run again')
    monkeypatch.setattr(worker, 'scan_task', unexpected_scan)
    worker.start_run(current)
    current = core.one('SELECT * FROM tasks WHERE id=?', (task['id'],))
    worker.ensure_run_scan(current)
    assert json.loads(current['progress'])['scan_run_id'] == current['run_id']


def test_old_reviewed_scan_is_refreshed_and_queue_names_active_task(state, monkeypatch):
    from importlib import import_module
    main = import_module('app.main')
    task = make_task(state, None)
    core.execute("UPDATE tasks SET status='scan_ready',last_scan=?,scan_id='old' WHERE id=?", (core.now() - 600, task['id']))
    core.progress(task['id'], 'scan_complete')
    with TestClient(app) as client:
        client.post('/api/auth/setup', json={'password': 'testing-password'})
        client.post(f"/api/tasks/{task['id']}/run")
        calls = []
        monkeypatch.setattr(worker, 'scan_task', lambda *args: calls.append('scan'))
        worker.start_run(core.one('SELECT * FROM tasks WHERE id=?', (task['id'],)))
        assert calls == ['scan']
        active = make_task(state)
        monkeypatch.setattr(worker, 'ACTIVE_TASK', active['id'])
        assert client.get(f"/api/tasks/{task['id']}").json()['waiting_for'] == active['name']


def test_upgrade_preserves_running_scan_and_shows_active_work(state, monkeypatch):
    from importlib import import_module
    main = import_module('app.main')
    task = make_task(state)
    core.execute("INSERT INTO runs(id,task_id,started,status) VALUES ('legacy-run',?,10,'running')", (task['id'],))
    core.execute("UPDATE tasks SET run_id='legacy-run',last_scan=20 WHERE id=?", (task['id'],))
    core.progress(task['id'], 'pack', percent=26)
    def unexpected(*args):
        raise AssertionError('Upgrade must preserve the scan and staged fragment state')
    monkeypatch.setattr(worker, 'scan_task', unexpected)
    current = core.one('SELECT * FROM tasks WHERE id=?', (task['id'],))
    worker.ensure_run_scan(current)
    monkeypatch.setattr(worker, 'ACTIVE_TASK', task['id'])
    view = main.task_view(core.one('SELECT * FROM tasks WHERE id=?', (task['id'],)))
    assert view['status'] == 'running' and view['progress']['stage'] == 'pack'
    assert view['progress']['percent'] == 26


def test_source_boundaries_and_initial_scan_only(state):
    (state / 'folder').mkdir()
    with TestClient(app) as client:
        client.post('/api/auth/setup', json={'username': 'owner', 'password': 'testing-password'})
        assert client.get('/api/browse', params={'path': str(state.parent)}).status_code == 400
        response = client.post('/api/tasks', json={'name': '文档', 'roots': [str(state)]})
        assert response.status_code == 200
        task = core.one('SELECT * FROM tasks WHERE id=?', (response.json()['id'],))
        assert task['operation'] == 'scan' and not task['initialized']
        assert not core.rows('SELECT * FROM groups')


def test_scan_exclusions_and_failed_scan_keeps_last_complete_result(state):
    (state / 'good.txt').write_text('first', encoding='utf-8')
    (state / 'video.tmp').write_bytes(b'partial')
    (state / '@eaDir').mkdir()
    (state / '@eaDir/thumb.jpg').write_bytes(b'thumb')
    task = make_task(state)
    result = scan_task(task)
    assert result == {'new': 1}
    old = core.rows('SELECT path FROM scan')
    with pytest.raises(Interrupted):
        scan_task(task, lambda: True)
    assert core.rows('SELECT path FROM scan') == old


def test_deletions_retain_latest_cloud_mapping(state):
    path = state / 'deleted.txt'
    core.execute('INSERT INTO files(task_id,path,root,relative,size,present,parts) VALUES (?,?,?,?,?,1,?)',
                 ('task', str(path), str(state), 'deleted.txt', 5, '[{"group":"existing"}]'))
    core.execute("INSERT INTO scan(task_id,path,kind,state) VALUES (?,?,'deleted','pending')", ('task', str(path)))
    worker.apply_deletions('task')
    item = core.one('SELECT * FROM files')
    assert item['present'] == 0
    assert json.loads(item['parts'])[0]['group'] == 'existing'


def test_overnight_window_and_manual_override(state):
    config = {'night_start': '22:00', 'night_end': '08:00'}
    assert worker.window(config, datetime(2026, 11, 5, 23, tzinfo=worker.TZ)) == (True, '2026-11-05')
    assert worker.window(config, datetime(2026, 11, 6, 7, tzinfo=worker.TZ)) == (True, '2026-11-05')
    assert worker.window(config, datetime(2026, 11, 6, 12, tzinfo=worker.TZ))[0] is False
    assert worker.window({'night_start': '', 'night_end': ''}) == (False, '')
    task = make_task(state)
    assert worker.allowed(task['id'])
    core.execute('UPDATE tasks SET manual=0 WHERE id=?', (task['id'],))
    assert not worker.allowed(task['id'])


def test_redaction(state):
    text = core.redact('secret fixture-token-only endpoint https://example.invalid/private-key/value')
    assert 'fixture-token-only' not in text and 'private-key' not in text


def test_idle_pause_cancel_and_delete_work_while_another_task_is_active(state,monkeypatch):
    active=make_task(state)
    idle=make_task(state)
    monkeypatch.setattr(worker,'ACTIVE_TASK',active['id'])
    (state/'keep.txt').write_text('original source')
    with TestClient(app) as client:
        client.post('/api/auth/setup',json={'password':'testing-password'})
        assert client.post(f"/api/tasks/{idle['id']}/pause").status_code==200
        detail=client.get(f"/api/tasks/{idle['id']}").json()
        assert detail['status']=='paused' and detail['can_remove']
        assert client.delete(f"/api/tasks/{idle['id']}").json()['cloud_files_retained']
        assert core.one('SELECT id FROM tasks WHERE id=?',(active['id'],))
        assert (state/'keep.txt').read_text()=='original source'
        another=make_task(state)
        client.post(f"/api/tasks/{another['id']}/cancel")
        assert core.one('SELECT operation FROM tasks WHERE id=?',(another['id'],))['operation'] is None


def test_active_task_and_pending_publication_cannot_be_deleted(state,monkeypatch):
    task=make_task(state)
    monkeypatch.setattr(worker,'ACTIVE_TASK',task['id'])
    with TestClient(app) as client:
        client.post('/api/auth/setup',json={'password':'testing-password'})
        client.post(f"/api/tasks/{task['id']}/pause")
        assert client.get(f"/api/tasks/{task['id']}").json()['status']=='pausing'
        assert client.delete(f"/api/tasks/{task['id']}").status_code==409
        monkeypatch.setattr(worker,'ACTIVE_TASK',None)
        worker.settle_pauses()
        assert core.one('SELECT status FROM tasks')['status']=='paused'
        core.execute("INSERT INTO publications(task_id) VALUES (?)",(task['id'],))
        assert client.delete(f"/api/tasks/{task['id']}").status_code==409


def test_hash_batches_bound_memory_and_commit_fewer_transactions(state,monkeypatch):
    from app import archive
    from app import scan
    for i in range(70):
        (state/('small-%03d.txt'%i)).write_text('fixture-'+str(i))
    task=make_task(state)
    scan_task(task)
    archive.prepare_candidates(task)
    assert core.one('SELECT COUNT(*) n FROM scan WHERE sha256 IS NOT NULL')['n']==70
    assert core.one('SELECT COUNT(*) n FROM scan WHERE text_content IS NOT NULL')['n']==70
    assert task['id'] in scan.HASH_TICKS


def test_cancel_releases_only_uncommitted_work_and_retains_sources(state):
    source = state / 'keep.txt'
    source.write_text('original', encoding='utf-8')
    task = make_task(state)
    directory = core.OUT / task['id'] / 'group'
    directory.mkdir(parents=True)
    (directory / 'partial.7z').write_bytes(b'owned pending output')
    core.execute("INSERT INTO groups(id,task_id,status,directory,created) VALUES (?,?,'building',?,?)",
                 ('group', task['id'], str(directory), core.now()))
    core.execute('UPDATE tasks SET paused=1,cancel_requested=1 WHERE id=?', (task['id'],))
    worker.settle_cancellations()
    current = core.one('SELECT * FROM tasks WHERE id=?', (task['id'],))
    assert current['operation'] is None and not current['paused']
    assert source.read_text() == 'original'
    assert not directory.exists()
    assert core.one('SELECT status FROM groups')['status'] == 'cancelled'


def test_night_window_validation_and_numeric_settings(state):
    with TestClient(app) as client:
        client.post('/api/auth/setup', json={'username': 'owner', 'password': 'testing-password'})
        assert client.put('/api/settings', json={'night_start': '22:00', 'night_end': '22:00'}).status_code == 400
        assert client.put('/api/settings', json={'quota_gb': '128'}).status_code == 200
        assert core.settings()['quota_gb'] == 128


def test_task_encryption_is_private_and_locked_after_archiving(state):
    from app import archive
    with TestClient(app) as client:
        client.post('/api/auth/setup', json={'username': 'owner', 'password': 'testing-password'})
        body = {'name': '独立加密', 'roots': [str(state)], 'encryption_mode': 'task',
                'encryption_password': 'different-fixture-password'}
        task_id = client.post('/api/tasks', json=body).json()['id']
        detail = client.get('/api/tasks/' + task_id).json()
        assert detail['encryption']['mode'] == 'task'
        assert detail['encryption']['configured']
        assert body['encryption_password'] not in json.dumps(detail)
        assert archive.password(task_id) == body['encryption_password']
        assert archive.password() == 'fixture-password-only'
        core.execute("INSERT INTO groups(id,task_id,status,directory,created) VALUES ('locked',?,'committed','unused',?)",
                     (task_id, core.now()))
        body['encryption_password'] = 'replacement-fixture-password'
        assert client.patch('/api/tasks/' + task_id, json=body).status_code == 409
        assert archive.password(task_id) == 'different-fixture-password'


def test_cloud_manifest_cache_reads_offline_and_refreshes_metadata_only(state, monkeypatch):
    from importlib import import_module
    from types import SimpleNamespace
    main = import_module('app.main')
    task = make_task(state, operation=None)
    source = state / 'cached.txt'
    source.write_text('new\n', encoding='utf-8')
    size, mtime, ctime = core.signature(source)
    parts = json.dumps([{'group': 'cached-group', 'volumes': ['data.7z']}])
    core.execute('''INSERT INTO files(task_id,path,root,relative,size,mtime_ns,ctime_ns,parts,text_content)
                    VALUES (?,?,?,?,?,?,?,?,?)''',
                 (task['id'], str(source), str(state), source.name, size, mtime, ctime, parts, 'old\n'))
    core.execute("UPDATE tasks SET cloud_dest='/bd/fixture-task' WHERE id=?", (task['id'],))
    core.execute("INSERT INTO objects(id,group_id,name,size,kind) VALUES ('data','cached-group','data.7z',42,'data')")
    core.execute("INSERT INTO objects(id,group_id,name,size,kind) VALUES ('parity','cached-group','recovery.par2',20,'parity')")
    calls = []
    class MetadataOnlyCloud:
        def __init__(self):
            calls.append('connect')
        def files(self, path, refresh=False):
            calls.append((path, refresh))
            return [SimpleNamespace(name='recovery.par2', size=20, isDirectory=False)]
        def close(self):
            calls.append('close')
    monkeypatch.setattr(main, 'Cloud', MetadataOnlyCloud)
    assert scan_task(task) == {'unchanged': 1}
    with TestClient(app) as client:
        client.post('/api/auth/setup', json={'username': 'owner', 'password': 'testing-password'})
        for _ in range(2):
            assert client.get(f"/api/tasks/{task['id']}/files").json()['total'] == 1
            assert client.get(f"/api/tasks/{task['id']}/changes").status_code == 200
            assert client.get(f"/api/tasks/{task['id']}/diff", params={'path': str(source)}).json()['text_available']
        assert calls == []
        result = client.post(f"/api/tasks/{task['id']}/refresh-cloud").json()
        assert result['abnormal_files'] == 1 and not result['downloaded_original_files']
        assert calls == ['connect', ('/bd/fixture-task/groups/cached-group', True), 'close']
        assert core.one('SELECT cloud_state FROM files')['cloud_state'] == 'missing'
        assert core.one('SELECT cloud_cache_at FROM tasks')['cloud_cache_at']
        assert scan_task(core.one('SELECT * FROM tasks')) == {'modified': 1}
