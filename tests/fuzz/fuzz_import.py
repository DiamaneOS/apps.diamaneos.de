#!/usr/bin/env python3
"""import-apks.py: the package name, version and file name from aapt2 decide where an APK is copied.

aapt2 is a stand-in that prints fuzzed badging. Property checks: every file the import writes is under
apps/packages/<package>/<version>/ in the work tree, with a package name of letters, digits, dots and
underscores and a version of digits only, and nothing else in the work tree changes.
"""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import types

import atheris

with atheris.instrument_imports():
    import fuzzlib
SOURCE = compile((fuzzlib.REPO / 'import-apks.py').read_text(), 'import-apks.py', 'exec')
TMP = Path(tempfile.mkdtemp(prefix='fuzz-import-'))
NAMES = ['app.grapheneos.apps', '../escape', '/abs/pkg', 'a/b', '..', '.', 'de.diamaneos.auditor/../../x',
         'App.Grapheneos.Apps', 'app.grapheneos.аpps', 'x' * 300, '']
CODES = ['37', '0', '-1', '../9', '1/2', '٣', '37 ', '1e3', '']
FILES = ['app.apk', 'split_config.arm64_v8a.apk', '..', 'a b.apk', '*.apk', '-rf.apk', '.hidden.apk']


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() if p.is_file() else None for p in root.rglob('*')}


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    name = NAMES[fdp.ConsumeIntInRange(0, len(NAMES) - 1)] if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(40)
    code = CODES[fdp.ConsumeIntInRange(0, len(CODES) - 1)] if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(12)
    split = fdp.ConsumeBool()
    filename = FILES[fdp.ConsumeIntInRange(0, len(FILES) - 1)]
    first = "package: name='%s' versionCode='%s' versionName='1'%s" % (name, code, " split='config.x'" if split else '')
    base = Path(tempfile.mkdtemp(dir=TMP))
    work, incoming = base / 'work', base / 'incoming'
    (work / 'apps/packages').mkdir(parents=True)
    incoming.mkdir()
    (base / 'canary').write_bytes(b'canary')
    try:
        src = incoming / filename if filename not in ('..',) else incoming / 'x.apk'
        src.write_bytes(b'apk')
        (Path(str(src) + '.idsig')).write_bytes(b'idsig')
        before = snapshot(base)
        fake = types.ModuleType('subprocess')
        fake.check_output = lambda argv, *a, **k: (first + '\n').encode()
        real = sys.modules['subprocess']
        cwd = os.getcwd()
        argv = sys.argv
        sys.modules['subprocess'] = fake
        os.chdir(work)
        sys.argv = ['import-apks.py', str(src)]
        try:
            exec(SOURCE, {'__name__': '__main__'})
            ok = True
        except Exception:
            ok = False
        finally:
            sys.modules['subprocess'] = real
            os.chdir(cwd)
            sys.argv = argv
        after = snapshot(base)
        packages = (work / 'apps/packages').resolve()
        for path in set(after) - set(before):
            full = (base / path).resolve()
            inside = full.is_relative_to(packages)
            parts = full.relative_to(packages).parts if inside else ()
            if not inside:
                fuzzlib.record('import wrote outside apps/packages', data, path)
            elif len(parts) >= 2 and not (all(c.isascii() and (c.isalnum() or c in '._') for c in parts[0])
                                          and parts[1].isascii() and parts[1].isdigit()):
                fuzzlib.record('import used an unsafe package or version directory', data, path)
            elif len(parts) > 3:
                fuzzlib.record('import nested deeper than package/version/file', data, path)
        for path in set(before) & set(after):
            if before[path] != after[path]:
                fuzzlib.record('import changed an existing file', data, path)
    finally:
        shutil.rmtree(base)


def write_seeds(directory):
    os.makedirs(directory, exist_ok=True)
    (Path(directory) / 'seed-0').write_bytes(bytes([1, 0, 1, 0, 0, 0]))
    (Path(directory) / 'seed-1').write_bytes(bytes([1, 1, 1, 0, 1, 1]))


if __name__ == '__main__':
    if sys.argv[1:2] == ['seeds']:
        write_seeds(sys.argv[2])
    else:
        atheris.instrument_all()
        atheris.Setup(sys.argv, TestOneInput)
        atheris.Fuzz()
