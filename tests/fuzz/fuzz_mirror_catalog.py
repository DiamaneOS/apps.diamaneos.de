#!/usr/bin/env python3
"""grapheneos-mirror.py needed_files() on catalog JSON: every listed path stays in its folder.

Input: catalog JSON bytes after the signature check. Property checks:
- each path is relative, normalised, ASCII, under packages/<name>/, with no empty or dot segment
- no path twice, and no two paths that differ only in case
- no package of ours or an excluded one, by any case or original name
- every download limit is a positive integer (bounded download size)
- only Refused stops it, any other exception is recorded.
"""
import json
import os
import posixpath
import sys

import atheris

with atheris.instrument_imports():
    import fuzzlib
    mirror = fuzzlib.load('grapheneos_mirror', 'grapheneos-mirror.py')
    import seeds

MAX_LIMIT = 4 * 1024 ** 3


def check(data):
    try:
        catalog = json.loads(data)
    except (ValueError, RecursionError):
        return
    if not isinstance(catalog, dict) or not isinstance(catalog.get('packages'), dict):
        return
    try:
        files = fuzzlib.guarded(2, mirror.needed_files, catalog)
    except mirror.Refused:
        return
    except fuzzlib.Slow:
        fuzzlib.record('needed_files slow', data)
        return
    except Exception as error:
        fuzzlib.record('needed_files raised ' + fuzzlib.where(error), data, repr(error))
        return
    seen, folded = set(), set()
    for path, kind, expected in files:
        parts = path.split('/')
        if (not path.isascii() or path.startswith('/') or posixpath.normpath(path) != path
                or parts[0] != 'packages' or len(parts) < 3 or any(p in ('', '.', '..') for p in parts)
                or '\\' in path or '\0' in path):
            fuzzlib.record('unsafe path ' + kind, data, path)
        name = parts[1] if len(parts) > 1 else ''
        if not mirror.listed(name, catalog['packages'].get(name, {})):
            fuzzlib.record('unlisted package fetched', data, path)
        if path in seen:
            fuzzlib.record('duplicate path ' + kind, data, path)
        if path.lower() in folded and path not in seen:
            fuzzlib.record('case-only duplicate path', data, path)
        seen.add(path)
        folded.add(path.lower())
        limit = {'apk': lambda: expected[2], 'br': lambda: expected[0], 'ina': lambda: expected[0],
                 'idsig': lambda: min(expected[0], mirror.MAX_IDSIG) if expected else mirror.MAX_IDSIG,
                 'icon': lambda: min(expected[1], mirror.MAX_ICON) if len(expected) > 1 else mirror.MAX_ICON}[kind]()
        if type(limit) is not int or limit < 0:
            fuzzlib.record('download limit not an integer ' + kind, data, repr(limit))
        elif limit > MAX_LIMIT:
            fuzzlib.record('download limit above 4 GiB ' + kind, data, repr(limit))
        sizes = [x for x in expected if not isinstance(x, str)]
        if any(type(x) is not int for x in sizes):
            fuzzlib.record('expected size not an integer ' + kind, data, repr(expected))


def TestOneInput(data):
    check(data)


def write_seeds(directory):
    os.makedirs(directory, exist_ok=True)
    for i, c in enumerate(seeds.catalogs()):
        with open(os.path.join(directory, f'seed-{i}.json'), 'wb') as f:
            f.write(c.body())


if __name__ == '__main__':
    if sys.argv[1:2] == ['seeds']:
        write_seeds(sys.argv[2])
    else:
        atheris.instrument_all()
        atheris.Setup(sys.argv, TestOneInput, custom_mutator=fuzzlib.json_mutator)
        atheris.Fuzz()
