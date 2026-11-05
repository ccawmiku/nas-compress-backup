"""Extract a current file from downloaded archives and a decrypted current-index.json."""
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index', required=True, type=Path)
    p.add_argument('--archives', required=True, type=Path, help='Task directory containing groups/<group-id>')
    p.add_argument('--path', required=True, help='Exact original path in the current index')
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--password-file', required=True, type=Path)
    p.add_argument('--7zz', dest='seven', default='7zz')
    args = p.parse_args()
    catalog = json.loads(args.index.read_text(encoding='utf-8'))
    record = next((f for f in catalog['files'] if f['path'] == args.path), None)
    if record is None:
        raise SystemExit('File is not present in the current index.')
    if args.output.exists():
        raise SystemExit('Output already exists; select a new destination.')
    password = args.password_file.read_text().strip('\r\n')
    digest = hashlib.sha256()
    written = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    partial = args.output.with_name(args.output.name + '.partial')
    if partial.exists():
        raise SystemExit('A partial output already exists; inspect it before retrying.')
    try:
        with partial.open('xb') as target:
            for part in sorted(record['parts'], key=lambda v: v['offset']):
                if part['offset'] != written:
                    raise RuntimeError('Non-contiguous fragment offsets.')
                pack = (args.archives / 'groups' / part['group'] / part['archive']).resolve()
                if args.archives.resolve() not in pack.parents:
                    raise RuntimeError('Archive path escapes the supplied directory.')
                proc = subprocess.Popen([args.seven, 'x', '-so', '-p' + password, str(pack), part['entry']], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                fragment_hash, length = hashlib.sha256(), 0
                for data in iter(lambda: proc.stdout.read(1024 * 1024), b''):
                    target.write(data)
                    digest.update(data)
                    fragment_hash.update(data)
                    length += len(data)
                if proc.wait() or length != part['length'] or fragment_hash.hexdigest() != part['sha256']:
                    raise RuntimeError('Fragment verification failed. Repair its group with PAR2 if necessary.')
                written += length
        if written != record['size'] or digest.hexdigest() != record['sha256']:
            raise RuntimeError('Whole-file verification failed.')
        os.replace(partial, args.output)
        print('File extracted and SHA-256 verified.')
    except BaseException:
        partial.unlink(missing_ok=True)
        raise


if __name__ == '__main__':
    main()
