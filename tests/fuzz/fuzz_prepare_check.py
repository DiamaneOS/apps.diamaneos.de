#!/usr/bin/env python3
"""prepare.py --check on catalogs signed with a throwaway key: the check passes only for our catalog, and
only for one that does not move back from the published catalog.

An input is a JSON object {"catalog": ..., "published": ..., "allow": [...]}. Both catalogs are signed with
real signify and checked through main(), as --check WORK KEY.pub PUBLISHED with an --allow-drop for each
entry of "allow". Without "published" it is the --first form. An input that is a bare catalog is checked
with --first. Property checks on a pass:
- every package is in the inventory, source DiamaneOS, without originalPackage, with the inventory's
  signers and its variants an object, each version an object with a decimal version code, a known
  channel, a single base.apk and a label, and the time an integer at or after the floor
- with a published catalog: the time is after the published one, each published package is still offered
  on every channel at the same or a higher version code, as the App Store picks it (findRPackage in
  Repo.kt), unless an allow-drop names the package or PACKAGE:CHANNEL, and each allow-drop names a drop
- --first takes no allow-drop.
Anything but SystemExit stopping the check is recorded.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile

import atheris

with atheris.instrument_imports():
    import fuzzlib
prepare = fuzzlib.load('prepare', 'prepare.py')
WORK = Path(tempfile.mkdtemp(prefix='fuzz-prepare-'))
KEYDIR = WORK / 'keys'
KEYDIR.mkdir()
PUB, SEC = fuzzlib.throwaway_signify_key(KEYDIR)
INVENTORY = prepare.load_inventory()
prepare.prepare(str(WORK / 'tree'))
PUBLISHED = WORK / 'published.sjson'
CHANNELS = ['alpha', 'beta', 'stable']


def sign(catalog, path):
    message = json.dumps(catalog, separators=(',', ':')).encode()
    path.write_bytes(message + b'\n' + fuzzlib.signify_sign(SEC, message, KEYDIR) + b'\n')


def picked(package, channel):
    """The version code a phone on channel is offered: the newest version of each channel, then the first of
    them, from least to most stable, at channel or more stable, else the most stable one. None without one."""
    newest = {}
    for code, variant in package.get('variants', {}).items():
        newest[variant.get('channel', 'stable')] = max(newest.get(variant.get('channel', 'stable'), 0), int(code))
    present = [c for c in CHANNELS if c in newest]
    for c in present:
        if CHANNELS.index(c) >= CHANNELS.index(channel):
            return newest[c]
    return newest[present[-1]] if present else None


def catalog_problems(catalog):
    problems = []
    if type(catalog.get('time')) is not int or catalog['time'] < prepare.MIN_TIME:
        problems.append('time')
    for name, package in catalog['packages'].items():
        listed = INVENTORY.get(name)
        if listed is None or not isinstance(package, dict):
            problems.append('not ours ' + name)
            continue
        if package.get('source') != 'DiamaneOS' or 'originalPackage' in package:
            problems.append('source ' + name)
        if sorted(package.get('signatures', [])) != sorted(listed['signatures']):
            problems.append('signers ' + name)
        variants = package.get('variants')
        if not isinstance(variants, dict):
            problems.append('variants not an object ' + name)
            continue
        for code, v in variants.items():
            if not re.fullmatch(r'[1-9][0-9]{0,18}', code) or not isinstance(v, dict) \
                    or v.get('channel', 'stable') not in CHANNELS:
                problems.append('version code or entry ' + name + '/' + code)
            elif v.get('apks') != ['base.apk'] or not str(v.get('label', '')).strip():
                problems.append('version ' + name + '/' + code)
    return problems


def published_problems(catalog, published, allow):
    problems, used = [], set()
    if catalog['time'] <= published['time']:
        problems.append('time not after the published one')
    for name, before in published['packages'].items():
        now = catalog['packages'].get(name, {})
        if picked(before, 'stable') is not None and picked(now, 'stable') is None:
            if name in allow:
                used.add(name)
            else:
                problems.append('dropped ' + name)
            continue
        for channel in CHANNELS:
            if picked(before, channel) is not None and picked(now, channel) < picked(before, channel):
                if name + ':' + channel in allow:
                    used.add(name + ':' + channel)
                else:
                    problems.append('moved back ' + name + ':' + channel)
    problems += ['unused allow-drop ' + a for a in sorted(set(allow) - used)]
    return problems


def TestOneInput(data):
    try:
        value = json.loads(data)
    except (ValueError, RecursionError):
        return
    if isinstance(value, dict) and 'catalog' in value:
        catalog, published, allow = value['catalog'], value.get('published'), value.get('allow', [])
    else:
        catalog, published, allow = value, None, []
    if not isinstance(allow, list):
        allow = []
    allow = [a for a in allow if isinstance(a, str) and '\0' not in a]
    args = ['--check'] + (['--first'] if published is None else []) + [str(WORK / 'tree'), str(PUB)]
    if published is not None:
        sign(published, PUBLISHED)
        args.append(str(PUBLISHED))
    for a in allow:
        args += ['--allow-drop', a]
    try:
        sign(catalog, WORK / 'tree' / prepare.CATALOG)
    except (ValueError, TypeError, RecursionError):
        return
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            prepare.main(args)
    except SystemExit:
        return
    except Exception as error:
        fuzzlib.record('check raised ' + fuzzlib.where(error), data, repr(error))
        return
    try:
        problems = catalog_problems(catalog)
        if published is None and allow:
            problems.append('allow-drop with --first')
        elif published is not None and not problems:
            problems += published_problems(catalog, published, set(allow))
    except Exception as error:
        fuzzlib.record('check passed a catalog the property checks cannot read', data, repr(error))
        return
    for p in problems:
        fuzzlib.record('check passed a catalog with a problem: ' + p.split(' ')[0], data, p)


def write_seeds(directory):
    os.makedirs(directory, exist_ok=True)

    def ours(time, code, channel='stable'):
        # Pinned makers' apps need their APK in the tree, so the seeds leave them out.
        packages = {}
        for name, p in INVENTORY.items():
            if name in prepare.PINNED:
                continue
            packages[name] = {k: p[k] for k in ('signatures', 'source', 'group', 'deps', 'isTopLevel') if k in p}
            if (WORK / 'tree/apps/packages' / name / 'icon.webp').exists():
                packages[name]['iconType'] = 'webp'
            packages[name]['variants'] = {str(code): {'versionCode': code, 'apks': ['base.apk'], 'label': name,
                                                      'channel': channel, 'apkHashes': ['0' * 64], 'minSdk': 37}}
        return {'time': time, 'packages': packages}

    first = ours(prepare.MIN_TIME + 100, 37)
    newer = ours(prepare.MIN_TIME + 200, 38)
    beta = ours(prepare.MIN_TIME + 200, 39, 'beta')
    dropped = ours(prepare.MIN_TIME + 200, 38)
    del dropped['packages']['de.diamaneos.auditor']
    older = ours(prepare.MIN_TIME + 200, 36)
    for i, value in enumerate([first, {'catalog': first}, {'catalog': newer, 'published': first},
                               {'catalog': beta, 'published': first},
                               {'catalog': dropped, 'published': first, 'allow': ['de.diamaneos.auditor']},
                               {'catalog': older, 'published': first, 'allow': ['app.grapheneos.apps:alpha']},
                               {'catalog': newer, 'published': first, 'allow': ['de.diamaneos.auditor']}]):
        (Path(directory) / f'seed-{i}.json').write_bytes(json.dumps(value).encode())


if __name__ == '__main__':
    if sys.argv[1:2] == ['seeds']:
        write_seeds(sys.argv[2])
    else:
        atheris.instrument_all()
        atheris.Setup(sys.argv, TestOneInput, custom_mutator=fuzzlib.json_mutator)
        atheris.Fuzz()
