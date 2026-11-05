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
        response = client.post('/api/auth/setup', json={'username': 'owner', 'password': 'testing-password'})
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
