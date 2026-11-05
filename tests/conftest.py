import os
import json
from pathlib import Path

os.environ['NCB_TESTING'] = '1'
os.environ['NCB_DISABLE_WORKER'] = '1'

import pytest
from app import core, worker


@pytest.fixture
def state(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.mkdir()
    for name, relative in [('DATA', 'data'), ('WORK', 'work'), ('OUT', 'output')]:
        monkeypatch.setattr(core, name, tmp_path / relative)
    monkeypatch.setattr(core, 'DB', core.DATA / 'state.sqlite3')
    monkeypatch.setattr(core, 'SECRET_FILE', core.DATA / 'secrets.json')
    monkeypatch.setattr(core, 'ROOTS', [source])
    monkeypatch.setattr(core, 'HOST_DATA', str(core.DATA))
    monkeypatch.setattr(core, 'HOST_WORK', str(core.WORK))
    monkeypatch.setattr(core, 'HOST_OUT', str(core.OUT))
    monkeypatch.setattr(core, 'PACK_PAYLOAD', 512 * 1024)
    monkeypatch.setattr(core, 'MAX_UPLOAD', 2 * 1024 * 1024)
    monkeypatch.setattr(core, 'GROUP_PACKS', 2)
    core.init()
    core.save_secrets({'archive_password': 'fixture-password-only', 'clouddrive_token': 'fixture-token-only'})
    core.update_settings({'local_source': '/Local', 'cloud_root': '/bd', 'quota_gb': 1})
    worker.STOP.clear()
    yield source
    for future in list(worker.FUTURES.values()):
        future.result(timeout=10)
    worker.FUTURES.clear()


def make_task(source, operation='backup'):
    task_id = core.identifier()
    core.execute("INSERT INTO tasks(id,name,roots,excludes,status,operation,manual,created,updated) VALUES (?,?,?,'[]','queued',?,1,?,?)",
                 (task_id, '测试任务', json.dumps([str(source)]), operation, core.now(), core.now()))
    return core.one('SELECT * FROM tasks WHERE id=?', (task_id,))
