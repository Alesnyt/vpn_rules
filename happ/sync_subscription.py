#!/usr/bin/python3
"""Sync only Happ release metadata; preserve the approved profile and live VPN."""
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import urllib.request

BASE = 'https://raw.githubusercontent.com/Alesnyt/vpn_rules/happ-data/'
STATE = Path('/var/lib/alexclubs-happ-routing')
DB = '/etc/x-ui/x-ui.db'
KEY = 'subRoutingRules'
PREFIX = 'happ://routing/add/'


def get(name, limit=65536):
    with urllib.request.urlopen(BASE + name, timeout=15) as response:
        if not response.geturl().startswith(BASE):
            raise ValueError('Unexpected source redirect')
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Source exceeds size limit')
    return data


def unpack(link):
    if not link.startswith(PREFIX) or len(link) > 8192 or '\n' in link:
        raise ValueError('Unsupported routing link')
    profile = json.loads(base64.b64decode(link[len(PREFIX):], validate=True))
    version = profile.pop('LastUpdated')
    if not isinstance(version, str) or not version.isdigit() or int(version) <= 0:
        raise ValueError('Invalid routing version')
    return profile, int(version)


def sync():
    approved = json.loads((STATE / 'approved-profile.json').read_text())
    manifest = json.loads(get('manifest.json'))
    raw = get('SUBSCRIPTION-HAPP.txt', 16384)
    if hashlib.sha256(raw).hexdigest() != manifest['files']['SUBSCRIPTION-HAPP.txt']['sha256']:
        raise ValueError('Routing release hash mismatch; keep previous version')
    link = raw.decode().strip()
    profile, version = unpack(link)
    if profile != approved or str(version) != manifest['subscription_profile_version']:
        raise ValueError('Profile policy changed; requires separate review')
    with sqlite3.connect(DB, timeout=15) as db:
        row = db.execute('SELECT value FROM settings WHERE key=?', (KEY,)).fetchone()
    if not row:
        raise ValueError('Routing setting missing')
    old = row[0]
    previous_profile, previous_version = unpack(old)
    if previous_profile != approved:
        raise ValueError('Local profile changed; refuse to overwrite')
    if version < previous_version:
        raise ValueError('Refuse to downgrade routing release')
    if version == previous_version:
        if old != link:
            raise ValueError('Same release version has different content')
        print('Happ routing release is current:', version)
        return
    for name in ('geosite.dat', 'geoip.dat'):
        if hashlib.sha256(get(name, 2 * 1024 * 1024)).hexdigest() != manifest['files'][name]['sha256']:
            raise ValueError('Geofile hash mismatch; keep previous version')
    pid = int(subprocess.check_output(['systemctl','show','x-ui','-p','MainPID','--value']))
    if b'StopPanelOnly' not in Path('/proc/' + str(pid) + '/exe').read_bytes():
        raise ValueError('Panel-only reload unavailable')
    with sqlite3.connect(DB, timeout=15) as db:
        db.execute('BEGIN IMMEDIATE')
        changed = db.execute('UPDATE settings SET value=? WHERE key=? AND value=?', (link, KEY, old)).rowcount
        if changed != 1:
            raise ValueError('Setting changed concurrently')
    try:
        os.kill(pid, signal.SIGHUP)
    except Exception:
        with sqlite3.connect(DB, timeout=15) as db:
            db.execute('UPDATE settings SET value=? WHERE key=? AND value=?', (old, KEY, link))
        raise
    (STATE / 'release.json').write_text(json.dumps({'source_commit':manifest['source_commit'], 'version':version}) + '\n')
    print('Happ routing release delivered:', version)


if __name__ == '__main__':
    sync()
