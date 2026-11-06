import json
import sys
from datetime import datetime
from importlib import import_module
from pathlib import Path

from fastapi.testclient import TestClient

from app import archive, core, worker
from app.main import app
from app.scan import scan_task
from conftest import make_task


def test_disable_night_limit_schedules_due_tasks_and_unblocks_active_work(state, monkeypatch):
    noon = datetime(2026, 11, 7, 12, tzinfo=worker.TZ)
    stamp = noon.timestamp()
    original_window = worker.window
    monkeypatch.setattr(worker, 'window', lambda config=None: original_window(config or core.settings(), noon))
    monkeypatch.setattr(core, 'now', lambda: stamp)
    core.update_settings({'night_start': '22:00', 'night_end': '08:00'})
    due, future, paused, first, disabled = [make_task(state, None) for _ in range(5)]
    for task in (due, future, paused, first, disabled):
        core.execute("UPDATE tasks SET initialized=1,manual=0,status='complete',last_completed=? WHERE id=?",
                     (stamp - 8 * 86400, task['id']))
    core.execute('UPDATE tasks SET last_completed=? WHERE id=?', (stamp, future['id']))
    core.execute('UPDATE tasks SET paused=1 WHERE id=?', (paused['id'],))
    core.execute('UPDATE tasks SET initialized=0 WHERE id=?', (first['id'],))
    core.execute('UPDATE tasks SET auto=0 WHERE id=?', (disabled['id'],))
    worker.schedule()
    assert core.one('SELECT operation FROM tasks WHERE id=?', (due['id'],))['operation'] is None
    assert not worker.allowed(due['id'])
    with TestClient(app) as client:
        client.post('/api/auth/setup', json={'password': 'testing-password'})
        assert client.put('/api/settings', json={'auto_schedule': False}).status_code == 200
        assert client.get('/api/overview').json()['night']['inside'] is True
        worker.schedule()
        current = core.one('SELECT * FROM tasks WHERE id=?', (due['id'],))
        assert current['operation'] == 'backup' and current['manual'] == 0
        assert worker.allowed(due['id'])
        for task in (future, paused, first, disabled):
            assert core.one('SELECT operation FROM tasks WHERE id=?', (task['id'],))['operation'] is None
        assert not worker.allowed(paused['id'])
        assert client.put('/api/settings', json={'auto_schedule': True}).status_code == 200
        assert not worker.allowed(due['id'])
        assert client.put('/api/settings', json={'auto_schedule': 'false'}).status_code == 400
    # All-day mode also works before night hours have ever been filled in.
    assert original_window({'auto_schedule': False, 'night_start': '', 'night_end': ''}, noon)[0]


def test_phase_switch_clears_previous_measurement_but_preserves_run_markers(state):
    task = make_task(state)
    core.progress(task['id'], 'hash', percent=99, phase_bytes=990, phase_total=1000,
                  current_path='previous.txt', scan_run_id='same-run', catalog_dirty=True)
    core.progress(task['id'], 'parity')
    value = json.loads(core.one('SELECT progress FROM tasks')['progress'])
    assert value['percent'] is None
    assert value['phase_bytes'] == value['phase_total'] == 0
    assert value['current_path'] == ''
    assert value['scan_run_id'] == 'same-run' and value['catalog_dirty']
    core.progress(task['id'], 'parity', percent=12.3, current_path='recovery.par2')
    core.progress(task['id'], 'parity', percent=18.7)
    assert json.loads(core.one('SELECT progress FROM tasks')['progress'])['current_path'] == 'recovery.par2'


def test_repeated_archive_subprocess_resets_percent_and_parses_decimals(state, monkeypatch):
    task = make_task(state)
    snapshots = []
    original = core.progress
    def observe(task_id, stage, **values):
        original(task_id, stage, **values)
        snapshots.append(json.loads(core.one('SELECT progress FROM tasks WHERE id=?', (task_id,))['progress']))
    monkeypatch.setattr(core, 'progress', observe)
    command = [sys.executable, '-c', "print('12.34%')"]
    for _ in range(2):
        archive.tool(command, task['id'], 'parity')
    assert [p['percent'] for p in snapshots] == [0, 12.34, 100, 0, 12.34, 100]


def test_small_pack_uses_actual_payload_and_source_progress_tracks_fragments(state, monkeypatch):
    main = import_module('app.main')
    (state / 'small.txt').write_bytes(b'x' * 123)
    task = make_task(state)
    scan_task(task)
    archive.prepare_candidates(task)
    group = archive.create_group(task)
    snapshots = []
    original = core.progress
    def observe(task_id, stage, **values):
        original(task_id, stage, **values)
        if stage == 'stage':
            snapshots.append(json.loads(core.one('SELECT progress FROM tasks WHERE id=?', (task_id,))['progress']))
    def seven(verb, output, *args, **kwargs):
        if verb == 'a':
            Path(str(output) + '.001').write_bytes(b'fixture archive')
    monkeypatch.setattr(core, 'progress', observe)
    monkeypatch.setattr(archive, 'seven', seven)
    assert archive.build_pack(task, group)
    assert snapshots[0]['phase_total'] == 123 < core.PACK_PAYLOAD
    assert snapshots[-1]['phase_bytes'] == snapshots[-1]['phase_total'] == 123
    assert snapshots[-1]['percent'] == 100
    current = core.one('SELECT * FROM tasks WHERE id=?', (task['id'],))
    stats = main.task_statistics(current)
    assert stats['source'] == {'count': 1, 'total': 123, 'prepared': 123}
    # A split large file advances the byte bar before the whole file is done.
    core.execute("UPDATE scan SET size=1000,offset=250,state='pending'")
    assert main.task_statistics(current)['source']['prepared'] == 250


def test_upload_progress_exposes_current_objects_and_confirmed_groups(state):
    main = import_module('app.main')
    task = make_task(state)
    core.execute("UPDATE tasks SET run_id='this-run' WHERE id=?", (task['id'],))
    for group_id, run_id, status in [('current', 'this-run', 'uploading'), ('done', 'this-run', 'committed'), ('old', 'old-run', 'committed')]:
        core.execute('INSERT INTO groups(id,task_id,run_id,status,directory,created) VALUES (?,?,?,?,?,?)',
                     (group_id, task['id'], run_id, status, 'fixture', core.now()))
    for object_id, group_id in [('active', 'current'), ('previous', 'old')]:
        core.execute("INSERT INTO objects(id,group_id,name,size,transferred,kind,status) VALUES (?,?,?,1000,123,'data','uploading')",
                     (object_id, group_id, object_id + '.7z'))
    stats = main.task_statistics(core.one('SELECT * FROM tasks WHERE id=?', (task['id'],)))
    assert stats['upload']['total'] == 1000 and stats['upload']['transferred'] == 123
    assert stats['active_uploads'] == [{'name': 'active.7z', 'size': 1000, 'transferred': 123}]
    assert stats['groups'] == {'count': 2, 'done': 1}
