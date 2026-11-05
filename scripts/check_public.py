"""Fail closed on common accidental credentials in tracked source files."""
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
paths = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
patterns = [r'gh[pousr]_[A-Za-z0-9]{30,}', r'github_pat_[A-Za-z0-9_]{40,}',
            r'https://api\.day\.app/[A-Za-z0-9]{15,}', r'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----']
bad = []
for name in paths:
    if not name:
        continue
    path = root / name
    if not path.is_file():
        continue
    text = path.read_text(encoding='utf-8-sig', errors='replace')
    if any(re.search(pattern, text) for pattern in patterns):
        bad.append(name)
if bad:
    raise SystemExit('Possible credentials detected in: ' + ', '.join(bad))
print('Tracked-source credential check passed.')

