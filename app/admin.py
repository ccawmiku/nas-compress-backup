"""Local administrator recovery: python -m app.admin reset"""
import sys
from . import core

if sys.argv[1:] != ['reset']:
    raise SystemExit('Usage: python -m app.admin reset')
core.init()
with core.connect() as db:
    db.execute('DELETE FROM sessions')
    db.execute('DELETE FROM admin')
print('Administrator cleared. Open the LAN web page to set a new account. Backup data was preserved.')

