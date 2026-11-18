#!/usr/bin/env python3
"""Whole mirror runs against a local stand-in upstream, with failures injected at any point.

Catalogs are signed with a throwaway signify key and checked with real signify. Each input sets the caps
and the clock, then picks up to four runs: which catalog upstream serves, which files it corrupts or
withholds, after how many file operations or fetches the run fails, how far the clock moves and whether
the served folder is emptied first. Upstream may also serve a catalog that lists a path twice or a key
twice. A run did its work when it ended without an exception or with Stale. Property checks after every run:
- only a valid signed catalog is published, and its time never goes back, even after the served folder
  is emptied
- the floor in STATE never goes down and is at least the time of every catalog published
- a catalog over the caps, or with a path or key twice, is never published, and nothing else is fetched
  for it
- every non-icon file the published catalog lists is present with upstream's bytes (never a mixed tree)
- a run that published nothing left the old catalog's files as they were, and changed an icon only to
  the published catalog's
- after a run that did its work, each icon of the published catalog that is present is upstream's, unless
  a fetch of it failed, which keeps the previous icon by design
- a run that did its work raised Stale exactly when the published catalog is older than MAX_AGE
- a file of a replaced catalog stays until KEEP_REPLACED after the run that replaced it, and after a run
  that did its work packages/ holds only the files the catalog lists and those still kept
- nothing outside the served folder and the state folder changes.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import types

import atheris

with atheris.instrument_imports():
    import fuzzlib
    import seeds
mirror = fuzzlib.load('grapheneos_mirror', 'grapheneos-mirror.py')
TMP = Path(tempfile.mkdtemp(prefix='fuzz-run-'))
fuzzlib.throwaway_signify_key(TMP)
mirror.KEY = str(TMP / 'fuzz-test.pub')
DAY = 24 * 3600


def catalogs():
    a = seeds.Catalog(time=1_780_000_000)
    a.apk('app.vanadium.browser', 10, b'browser 10', icon='webp')
    a.apk('app.grapheneos.pdfviewer', 20, b'pdf 20')
    b = copy.deepcopy(a)
    b.time = 1_780_000_100
    b.apk('app.vanadium.browser', 11, b'browser 11')
    b.apk('app.grapheneos.pdfviewer', 21, b'pdf 21')
    b.delta('app.grapheneos.pdfviewer', 21, {20: b'delta 20 to 21'})
    # A new icon at the same path.
    b.files['packages/app.vanadium.browser/icon.webp'] = seeds.webp() + b'new'
    b.packages['app.vanadium.browser'].update(iconSize=len(seeds.webp()) + 3,
                                              iconSha256=hashlib.sha256(seeds.webp() + b'new').hexdigest())
    c = copy.deepcopy(b)
    c.time = 1_780_000_200
    del c.packages['app.vanadium.browser']['variants']['10']
    for path in [p for p in c.files if p.startswith('packages/app.vanadium.browser/10/')]:
        del c.files[path]
    c.apk('app.grapheneos.camera.extra', 1, b'extra 1', icon='png')
    # A path listed twice: browser 11's APK, with all its columns.
    d = copy.deepcopy(c)
    d.time = 1_780_000_300
    twice = d.packages['app.vanadium.browser']['variants']['11']
    for column in ('apks', 'apkHashes', 'apkSizes', 'apkGzSizes', 'apkBrSizes', 'apkBrHashes',
                   'v4SignatureSizes', 'v4SignatureHashes'):
        twice[column] = twice[column] * 2
    result = []
    for cat in (a, b, c, d):
        result.append({'body': cat.body(), 'files': dict(cat.files), 'time': cat.time,
                       'needed': None if cat is d else {p: len(v) for p, v in cat.files.items()}})
    # A key listed twice: the catalog's time, the first one newer.
    result.append({'body': b'{"time":1780000400,' + c.body()[1:], 'files': dict(c.files), 'time': 1_780_000_400,
                   'needed': None})
    for cat in result:
        line = fuzzlib.signify_sign(TMP / 'fuzz-test.sec', cat['body'], TMP)
        cat['files'][mirror.CATALOG] = cat['signed'] = cat['body'] + b'\n' + line + b'\n'
    return result


CATALOGS = catalogs()
BY_BYTES = {c['signed']: c for c in CATALOGS}
DEFAULT_CAPS = (mirror.MAX_FILES, mirror.MAX_FILE, mirror.MAX_TOTAL)
SIZES = sorted({max(c['needed'].values()) for c in CATALOGS if c['needed']})
TOTALS = sorted({sum(c['needed'].values()) for c in CATALOGS if c['needed']})
COUNTS = sorted({len(c['needed']) for c in CATALOGS if c['needed']})


class Injected(Exception):
    pass


class Faults:
    def __init__(self, at):
        self.at, self.count = at, 0

    def tick(self):
        self.count += 1
        if self.count == self.at:
            raise Injected()


def fake_os(faults):
    space = types.SimpleNamespace(**{k: getattr(os, k) for k in dir(os) if not k.startswith('__')})
    for name in ('replace', 'remove', 'rmdir', 'makedirs', 'fsync'):
        real = getattr(os, name)

        def wrapped(*args, _real=real, **kwargs):
            faults.tick()
            return _real(*args, **kwargs)
        setattr(space, name, wrapped)
    space.path = os.path
    return space


def make_fetch(files, damage, faults, requested):
    def fetch(path, limit, out=None):
        requested.append(path)
        faults.tick()
        if path not in files or damage.get(path) == 'missing':
            raise mirror.Refused(path + ': HTTP 404')
        data = files[path]
        how = damage.get(path)
        if how == 'truncate':
            data = data[:len(data) // 2]
        elif how == 'flip' and data:
            data = bytes([data[0] ^ 1]) + data[1:]
        elif how == 'grow':
            data = data + b'\0' * 64
        if len(data) > limit:
            raise mirror.Refused(path + ' exceeds')
        if out is None:
            return data
        out.write(data)
        return len(data)
    return fetch


def tree(root):
    result = {}
    for directory, _dirs, names in os.walk(root):
        for name in names:
            path = Path(directory) / name
            result[str(path.relative_to(root))] = path.read_bytes() if not path.is_symlink() else b'LINK'
    return result


def is_icon(path):
    return '/icon.' in path


def over_caps(cat):
    files, size, total = mirror.MAX_FILES, mirror.MAX_FILE, mirror.MAX_TOTAL
    sizes = cat['needed'].values()
    return len(sizes) > files or max(sizes) > size or sum(sizes) > total


def check_run(data, s, cat, before, after, outcome, requested, damage, clock):
    """s holds what earlier runs of this input published. outcome is 'ok', 'stale' or 'failed'."""
    record = fuzzlib.record
    worked = outcome in ('ok', 'stale')
    old, new = before.get(mirror.CATALOG), after.get(mirror.CATALOG)
    changed = new is not None and new != old
    published = BY_BYTES.get(new) if new is not None else None
    if new is not None and (published is None or published['needed'] is None):
        record('published catalog is not a valid signed one', data)
        return False
    if cat['needed'] is None or over_caps(cat):
        if new == cat['signed']:
            record('published a catalog over the caps or with a path or key twice', data)
        if requested[1:]:
            record('fetched files for a catalog over the caps or with a path or key twice', data,
                   ' '.join(requested[1:3]))
    if published is not None:
        if published['time'] < s['max_published']:
            record('published catalog went back in time', data)
        s['max_published'] = max(s['max_published'], published['time'])
    floor_path = s['state'] / 'catalogs.json'
    if floor_path.is_file():
        try:
            floor = json.loads(floor_path.read_text())['floor']
        except (ValueError, KeyError, TypeError):
            record('STATE catalogs.json unreadable', data)
            return False
        if floor < s['floor'] or floor < s['max_published']:
            record('floor in STATE went down or below a published catalog', data, f'{floor} {s["max_published"]}')
        s['floor'] = floor
    if changed:
        if old is not None and old in BY_BYTES:
            for path in set(BY_BYTES[old]['needed']) - set(published['needed']):
                until = clock + mirror.KEEP_REPLACED
                if path in before:
                    s['kept'][path] = max(until, s['kept'].get(path, 0))
        s['kept_icons'] = {}
    if published is None:
        return True
    # A failed fetch of the published catalog's icon keeps the previous icon, whatever was there.
    for path in requested:
        if is_icon(path) and cat is published and (damage.get(path) or path not in cat['files']):
            s['kept_icons'][path] = after.get(path)
    for path in published['needed']:
        if is_icon(path):
            if path in after and after[path] != published['files'][path]:
                if not changed and after[path] != before.get(path):
                    record('run changed an icon to one the published catalog does not list', data, path)
                elif worked and s['kept_icons'].get(path) != after[path]:
                    record('served icon does not match the published catalog after a run that did its work',
                           data, path)
        elif path not in after:
            record('published catalog lists a missing file ' + ('after its work' if worked else 'after failure'),
                   data, path)
        elif after[path] != published['files'][path]:
            record('published catalog lists a file that differs ' + ('after its work' if worked else 'after failure'),
                   data, path)
    if not changed and old is not None:
        moved = [p for p in published['needed'] if not is_icon(p) and before.get(p) != after.get(p)]
        if moved:
            record('old catalog files changed without a new catalog', data, ' '.join(moved))
    for path, until in s['kept'].items():
        if until > clock and path not in after:
            record('file of a replaced catalog removed before KEEP_REPLACED', data, path)
    age = clock - published['time']
    if outcome == 'ok' and age > mirror.MAX_AGE:
        record('run did its work without an alert on a catalog older than MAX_AGE', data)
    if outcome == 'stale' and (age <= mirror.MAX_AGE or new != cat['signed']):
        record('Stale for a catalog not older than MAX_AGE or not the one served', data)
    if worked:
        allowed = set(published['needed']) | {p for p, until in s['kept'].items() if until > clock}
        # Pruning covers packages/. A publication stopped before its rename may leave the catalog's .tmp beside it.
        extra = [p for p in after if p.startswith('packages/') and p not in allowed]
        if extra:
            record('run that did its work left files no kept catalog lists', data, ' '.join(sorted(extra)[:3]))
    return True


def plan(data):
    """The caps, the clock's start and up to four runs. A run is the catalog upstream serves, the files it
    damages, after how many file operations or fetches the run fails, how far the clock moves before it and
    whether the served folder is emptied first."""
    fdp = atheris.FuzzedDataProvider(data)
    caps = (fdp.PickValueInList([DEFAULT_CAPS[0]] + COUNTS[:-1]), fdp.PickValueInList([DEFAULT_CAPS[1], SIZES[-1] - 1]),
            fdp.PickValueInList([DEFAULT_CAPS[2]] + [t - 1 for t in TOTALS]))
    start = CATALOGS[0]['time'] + fdp.PickValueInList([60, DAY, mirror.MAX_AGE - 60, mirror.MAX_AGE + 60])
    runs = []
    for _run in range(fdp.ConsumeIntInRange(1, 4)):
        cat = fdp.ConsumeIntInRange(0, len(CATALOGS) - 1)
        damage = {}
        for path in sorted(CATALOGS[cat]['files']):
            choice = fdp.ConsumeIntInRange(0, 15)
            if choice < 4:
                damage[path] = ('missing', 'truncate', 'flip', 'grow')[choice]
        fault = fdp.ConsumeIntInRange(0, 40)
        advance = fdp.PickValueInList([0, 60, mirror.KEEP_REPLACED - 60, mirror.KEEP_REPLACED + 60, mirror.MAX_AGE])
        runs.append((cat, damage, fault, advance, fdp.ConsumeIntInRange(0, 7) == 0))
    return caps, start, runs


def TestOneInput(data):
    execute(data, *plan(data))


def execute(data, caps, start, runs):
    base = Path(tempfile.mkdtemp(dir=TMP))
    root, state, outside = base / 'served', base / 'state', base / 'outside'
    root.mkdir()
    outside.mkdir()
    (outside / 'canary').write_bytes(b'canary')
    real_os, real_fetch, real_now = mirror.os, mirror.fetch, mirror.now
    mirror.MAX_FILES, mirror.MAX_FILE, mirror.MAX_TOTAL = caps
    clock = [start]
    mirror.now = lambda: clock[0]
    s = {'max_published': 0, 'floor': 0, 'kept': {}, 'kept_icons': {}, 'state': state}
    try:
        for index, damage, fault, advance, empty in runs:
            cat = CATALOGS[index]
            faults = Faults(fault)
            clock[0] += advance
            if empty:
                shutil.rmtree(root)
                root.mkdir()
                s['kept'], s['kept_icons'] = {}, {}
            before = tree(root)
            requested = []
            mirror.os = fake_os(faults)
            mirror.fetch = make_fetch(cat['files'], damage, faults, requested)
            outcome = 'failed'
            try:
                fuzzlib.guarded(20, mirror.mirror, str(root), str(state))
                outcome = 'ok'
            except mirror.Stale:
                outcome = 'stale'
            except (mirror.Refused, Injected):
                pass
            except fuzzlib.Slow:
                fuzzlib.record('mirror run slow', data)
            except Exception as error:
                fuzzlib.record('mirror run raised ' + fuzzlib.where(error), data, repr(error))
            finally:
                mirror.os, mirror.fetch = real_os, real_fetch
            after = tree(root)
            if not check_run(data, s, cat, before, after, outcome, requested, damage, clock[0]):
                return
            if sorted(os.listdir(base)) not in (['outside', 'served'], ['outside', 'served', 'state']) or \
                    tree(outside) != {'canary': b'canary'}:
                fuzzlib.record('run touched files outside its folders', data)
            for directory, dirs, names in os.walk(root):
                for name in dirs + names:
                    if (Path(directory) / name).is_symlink():
                        fuzzlib.record('run made a symlink', data)
    finally:
        mirror.os, mirror.fetch, mirror.now = real_os, real_fetch, real_now
        mirror.MAX_FILES, mirror.MAX_FILE, mirror.MAX_TOTAL = DEFAULT_CAPS
        shutil.rmtree(base)


def write_seeds(directory):
    os.makedirs(directory, exist_ok=True)
    for i, seed in enumerate([bytes([0, 0, 0, 0, 1, 0] + [9] * 40 + [255, 0, 0]),
                              bytes([0, 0, 0, 0, 2, 0] + [9] * 40 + [255, 1, 9, 1] + [9] * 40 + [255, 3, 9]),
                              bytes([0, 0, 0, 3, 3, 1] + [9] * 40 + [12, 2, 9, 2] + [9] * 40 + [255, 3, 9, 0]
                                    + [0] * 40 + [5, 4, 9])]):
        (Path(directory) / f'seed-{i}').write_bytes(seed)


if __name__ == '__main__':
    if sys.argv[1:2] == ['seeds']:
        write_seeds(sys.argv[2])
    else:
        atheris.instrument_all()
        atheris.Setup(sys.argv, TestOneInput)
        atheris.Fuzz()
