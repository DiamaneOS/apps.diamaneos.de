#!/usr/bin/env python3
"""Signed catalog framing and signature checks of grapheneos-mirror.py and prepare.py, with real signify.

The seeds are catalogs signed with a throwaway key made for the corpus ($FUZZ_KEYS). Property checks:
- a catalog is accepted only if its JSON bytes are exactly a message the throwaway key signed
- an accepted catalog's signature line is the one signify wrote (records malleable encodings)
- the mirror and prepare.py accept the same framings
- nothing but Refused (mirror) or SystemExit (prepare) stops it.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

import atheris

with atheris.instrument_imports():
    import fuzzlib
    import seeds
mirror = fuzzlib.load('grapheneos_mirror', 'grapheneos-mirror.py')
prepare = fuzzlib.load('prepare', 'prepare.py')

KEYS = Path(os.environ.get('FUZZ_KEYS', 'keys'))
WORK = Path(tempfile.mkdtemp(prefix='fuzz-signed-'))
SIGNED = {}


def setup():
    KEYS.mkdir(parents=True, exist_ok=True)
    if not (KEYS / 'fuzz-test.pub').exists():
        fuzzlib.throwaway_signify_key(KEYS)
    mirror.KEY = str(KEYS / 'fuzz-test.pub')
    signed = KEYS / 'signed.json'
    if signed.exists():
        SIGNED.update(json.loads(signed.read_text()))
    (WORK / 'apps').mkdir()


def sign(message):
    line = fuzzlib.signify_sign(KEYS / 'fuzz-test.sec', message, WORK)
    SIGNED[hashlib.sha256(message).hexdigest()] = line.decode()
    (KEYS / 'signed.json').write_text(json.dumps(SIGNED))
    return message + b'\n' + line + b'\n'


def TestOneInput(data):
    try:
        catalog = mirror.verify_catalog(data, str(WORK / 'state'))
        mirror_ok = True
    except mirror.Refused:
        mirror_ok = False
    except Exception as error:
        mirror_ok = None
        fuzzlib.record('mirror verify raised ' + fuzzlib.where(error), data, repr(error))
    (WORK / prepare.CATALOG).write_bytes(data)
    try:
        prepare.signed_catalog(str(WORK / prepare.CATALOG), mirror.KEY)
        prepare_ok = True
    except SystemExit:
        prepare_ok = False
    except Exception as error:
        prepare_ok = None
        fuzzlib.record('prepare verify raised ' + fuzzlib.where(error), data, repr(error))
    if mirror_ok is not None and prepare_ok is not None and mirror_ok != prepare_ok:
        fuzzlib.record('mirror and prepare disagree', data, f'mirror {mirror_ok} prepare {prepare_ok}')
    if mirror_ok or prepare_ok:
        message = data[:-102]
        line = SIGNED.get(hashlib.sha256(message).hexdigest())
        if line is None:
            fuzzlib.record('accepted a message the key never signed', data)
        elif data[-101:-1].decode('ascii', 'replace') != line:
            fuzzlib.record('accepted another signature line for a signed message', data,
                           data[-101:-1].decode('ascii', 'replace') + ' vs ' + line)


def write_seeds(directory):
    os.makedirs(directory, exist_ok=True)
    for i, c in enumerate(seeds.catalogs()):
        (Path(directory) / f'seed-{i}.sjson').write_bytes(sign(c.body()))
    (Path(directory) / 'seed-empty.sjson').write_bytes(sign(b'{"time":1792600000,"packages":{}}'))


if __name__ == '__main__':
    setup()
    if sys.argv[1:2] == ['seeds']:
        write_seeds(sys.argv[2])
    else:
        atheris.instrument_all()
        atheris.Setup(sys.argv, TestOneInput)
        atheris.Fuzz()
