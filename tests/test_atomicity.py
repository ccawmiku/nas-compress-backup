import json
from pathlib import Path

import pytest
from app import core,archive,worker
from app.cloud import CloudError
from conftest import make_task


@pytest.mark.parametrize('receipt_reached_cloud',[False,True])
def test_failed_publication_preserves_visible_index_and_recovers_same_intent(state,monkeypatch,receipt_reached_cloud):
    task=make_task(state)
    core.execute("UPDATE tasks SET cloud_dest='/bd/fixture' WHERE id=?",(task['id'],))
    path=str(state/'current.txt')
    old={'task_id':task['id'],'path':path,'root':str(state),'relative':'current.txt','size':3,
         'mtime_ns':1,'ctime_ns':1,'sha256':'old','text_content':None}
    with core.connect() as db:
        archive._record_file(db,task['id'],old,[])
        core.commit_files(db,task['id'])
    new={**old,'size':7,'sha256':'new'}
    with core.connect() as db:
        archive._record_file(db,task['id'],new,[])
    directory=core.OUT/task['id']/'group'
    directory.mkdir(parents=True)
    (directory/'keep.7z').write_bytes(b'retain until publication succeeds')
    core.execute("INSERT INTO groups(id,task_id,status,directory,created) VALUES ('group',?,'uploading',?,?)",(task['id'],str(directory),core.now()))
    def seven(verb,path,*args,**kwargs):
        if verb=='a':
            Path(path).write_bytes(b'encrypted test index')
    monkeypatch.setattr(archive,'seven',seven)
    remote={}
    fail=[True]
    class Cloud:
        def close(self): pass
        def task_destination(self,task): return '/bd/fixture'
        def ensure_folder(self,parent,name): return parent+'/'+name
        def prune_catalog(self,*args): pass
    cloud=Cloud()
    monkeypatch.setattr(worker,'Cloud',lambda:cloud)
    def transfer(cloud,source,dest,expected,**kwargs):
        marker=source.endswith('.json')
        if marker and fail[0] and not receipt_reached_cloud:
            raise CloudError('injected receipt failure')
        remote[source]=expected
        if marker and fail[0]:
            raise CloudError('injected failure after receipt reached cloud')
    monkeypatch.setattr(worker,'wait_copy',transfer)
    with pytest.raises(CloudError):
        worker.publish_catalog(task,cloud,'group')
    assert core.one('SELECT sha256 FROM files_current')['sha256']=='old'
    assert core.one('SELECT status FROM groups')['status']=='uploading'
    assert core.one('SELECT generation FROM publications')['generation']==1
    assert directory.exists()
    marker=json.loads(core.one('SELECT objects FROM publications')['objects'])[-1]['name']
    # A restarted process reads the persisted intent and finishes that exact receipt.
    fail[0]=False
    worker.recover_publications()
    assert core.one('SELECT sha256 FROM files_current')['sha256']=='new'
    assert core.one('SELECT status FROM groups')['status']=='committed'
    assert core.one('SELECT catalog_generation FROM tasks')['catalog_generation']==1
    assert not core.rows('SELECT * FROM publications')
    assert not core.rows('SELECT * FROM file_edits')
    assert not directory.exists()
    assert len([name for name in remote if name.endswith(marker)])==1


def test_rollback_restores_old_records_and_removes_unpublished_additions(state):
    task=make_task(state)
    original={'path':str(state/'old.txt'),'root':str(state),'relative':'old.txt','size':3,
              'mtime_ns':1,'ctime_ns':1,'sha256':'old','text_content':'old'}
    with core.connect() as db:
        archive._record_file(db,task['id'],original,[])
        core.commit_files(db,task['id'])
        archive._record_file(db,task['id'],{**original,'sha256':'new','text_content':'changed'},[])
        archive._record_file(db,task['id'],{**original,'path':str(state/'new.txt')},[])
    assert core.one('SELECT COUNT(*) n FROM files_current')['n']==1
    with core.connect() as db:
        core.rollback_files(db,task['id'])
    assert core.one('SELECT COUNT(*) n FROM files')['n']==1
    assert core.one('SELECT sha256 FROM files')['sha256']=='old'
    assert core.settings()['text_cache_bytes']==3
