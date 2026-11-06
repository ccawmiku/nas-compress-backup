"""Bounded synthetic PAR2 benchmark; never touches NAS sources or cloud files."""
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from app.archive import parity_layout


def run(command,directory):
    start=time.perf_counter()
    proc=subprocess.Popen(command,cwd=directory,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    peak=0
    while proc.poll() is None:
        try:
            for line in Path('/proc',str(proc.pid),'status').read_text().splitlines():
                if line.startswith('VmRSS:'):
                    peak=max(peak,int(line.split()[1]))
        except OSError:
            pass
        time.sleep(0.01)
    if proc.returncode:
        raise RuntimeError('PAR2 benchmark command failed')
    return {'seconds':round(time.perf_counter()-start,3),'peak_rss_mib':round(peak/1024,1)}


with tempfile.TemporaryDirectory(prefix='ncb-par2-benchmark-') as temp:
    base=Path(temp)
    names=['part-%d.bin'%i for i in range(5)]
    size=4*1024**2
    for name in names:
        (base/name).write_bytes(os.urandom(size))
    expected=hashlib.sha256((base/names[0]).read_bytes()).hexdigest()
    results={}
    for mode in ('previous','optimized'):
        directory=base/mode
        directory.mkdir()
        for name in names:
            os.link(base/name,directory/name)
        if mode=='previous':
            block=max(4096,math.ceil(size*5/4096/4)*4)
            count=math.ceil(size/block)+2
            volumes,memory=2,128
        else:
            block,count,volumes=parity_layout(size*5,size)
            memory=96
        result=run([os.getenv('NCB_PAR2','par2'),'create','-qq','-t1','-m%d'%memory,
                    '-s%d'%block,'-c%d'%count,'-u','-n%d'%volumes,'recovery.par2',*names],directory)
        result.update({'block_bytes':block,'recovery_blocks':count,'memory_budget_mib':memory})
        results[mode]=result
        if mode=='optimized':
            (directory/names[0]).unlink()
            run([os.getenv('NCB_PAR2','par2'),'repair','-q','-t1','-m96','recovery.par2'],directory)
            assert hashlib.sha256((directory/names[0]).read_bytes()).hexdigest()==expected
    results['complete_missing_file_repair']='passed'
    print(json.dumps(results))
