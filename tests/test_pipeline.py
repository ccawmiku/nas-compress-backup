import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import core, worker, archive
from conftest import make_task


class FakeCloud:
    remote = {}
    tasks = []

    def close(self):
        pass

    def task_destination(self, task):
        result = '/bd/群晖压缩备份/' + task['id']
        core.execute('UPDATE tasks SET cloud_dest=? WHERE id=?', (result, task['id']))
        return result

    def ensure_folder(self, parent, name):
        return parent.rstrip('/') + '/' + name

    def files(self, path, refresh=False):
        prefix = path.rstrip('/') + '/'
        return [SimpleNamespace(name=k[len(prefix):], size=len(v), isDirectory=False)
                for k, v in self.remote.items() if k.startswith(prefix) and '/' not in k[len(prefix):]]

    def copy_tasks(self):
        return self.tasks

    def uploads(self, destination):
        return {}

    def start_copy(self, source, destination, overwrite=False):
        relative = source.split('/nas-compress-backup/', 1)[1]
        path = core.OUT / relative
        data = path.read_bytes()
        self.remote[destination + '/' + path.name] = data
        import time
        self.tasks.append(SimpleNamespace(sourcePath=source, destPath=destination,
            status=3, failedFiles=0, failedFolders=0, uploadedBytes=len(data),
            startTime=SimpleNamespace(seconds=int(time.time()), nanos=time.time_ns() % 1_000_000_000)))

    def delete_owned_group(self, path, task_dest):
        assert path.startswith(task_dest + '/groups/')
        for key in list(self.remote):
            if key.startswith(path + '/'):
                del self.remote[key]


def tools_available():
    return shutil.which(os.getenv('NCB_7ZZ', '7zz')) and shutil.which(os.getenv('NCB_PAR2', 'par2'))


def process(task):
    worker.start_run(task)
    for _ in range(30):
        current = core.one('SELECT * FROM tasks WHERE id=?', (task['id'],))
        if current['operation'] is None:
            return current
        worker.one_group(current)
    raise AssertionError('Pipeline did not finish')


@pytest.mark.skipif(not tools_available(), reason='7zz and par2 are required for integration tests')
def test_bounded_fragment_pipeline_incremental_and_par2(state, monkeypatch, tmp_path):
    FakeCloud.remote = {}
    FakeCloud.tasks = []
    monkeypatch.setattr(worker, 'Cloud', FakeCloud)
    large = state / '大文件.mp4'
    content = os.urandom(core.PACK_PAYLOAD * 5 + 71)
    large.write_bytes(content)
    (state / '说明.txt').write_text('第一版\n', encoding='utf-8')
    task = make_task(state)
    result = process(task)
    assert result['status'] == 'complete'
    files = core.rows('SELECT * FROM files WHERE task_id=?', (task['id'],))
    assert len(files) == 2
    record = next(f for f in files if f['path'] == str(large))
    parts = json.loads(record['parts'])
    assert len(parts) == 6
    assert record['sha256'] == hashlib.sha256(content).hexdigest()
    assert core.disk_used() == 0
    assert all(len(value) <= core.MAX_UPLOAD for value in FakeCloud.remote.values())
    # Reassemble the large file using real encrypted archives, not its original source.
    restored = bytearray()
    extracted = tmp_path / 'readback'
    extracted.mkdir()
    for part in parts:
        prefix = '/bd/群晖压缩备份/' + task['id'] + '/groups/' + part['group'] + '/'
        pack = extracted / part['archive']
        pack.write_bytes(FakeCloud.remote[prefix + part['archive']])
        run = subprocess.run([os.getenv('NCB_7ZZ', '7zz'), 'x', '-so', '-pfixture-password-only', str(pack), part['entry']], capture_output=True)
        assert run.returncode == 0
        restored.extend(run.stdout)
    assert bytes(restored) == content
    # Delete one complete cloud object in a scratch replica and repair it with PAR2.
    group_id = parts[0]['group']
    prefix = '/bd/群晖压缩备份/' + task['id'] + '/groups/' + group_id + '/'
    repair = tmp_path / 'repair'
    repair.mkdir()
    for remote, data in FakeCloud.remote.items():
        if remote.startswith(prefix):
            (repair / remote[len(prefix):]).write_bytes(data)
    missing = repair / parts[0]['archive']
    expected = core.digest_file(missing)
    missing.unlink()
    subprocess.run([os.getenv('NCB_PAR2', 'par2'), 'repair', '-q', str(repair / 'recovery.par2')], cwd=repair, check=True, capture_output=True)
    assert core.digest_file(missing) == expected
    # Next run is incremental: a deleted NAS source keeps its last cloud mapping.
    before = len([k for k in FakeCloud.remote if '/groups/' in k])
    large.unlink()
    (state / '说明.txt').write_text('第二版\n', encoding='utf-8')
    core.execute("UPDATE tasks SET operation='backup',status='queued',run_id=NULL,manual=1 WHERE id=?", (task['id'],))
    result = process(core.one('SELECT * FROM tasks WHERE id=?', (task['id'],)))
    assert result['status'] == 'complete'
    assert core.one('SELECT present FROM files WHERE path=?', (str(large),))['present'] == 0
    assert core.one('SELECT sha256 FROM files WHERE path=?', (str(state / '说明.txt'),))['sha256'] == hashlib.sha256('第二版\n'.encode()).hexdigest()
    assert core.disk_used() == 0

