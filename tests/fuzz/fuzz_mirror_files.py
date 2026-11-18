#!/usr/bin/env python3
"""The mirror's checks of downloaded files: gzip APKs, .br/.ina by hash, v4 signatures and icons.

Input: one byte choosing a reference entry, then the downloaded bytes. Property checks:
- an accepted .gz unpacks to exactly the catalog's APK bytes
- an accepted .br, .ina or hashed file is exactly the catalog's bytes
- an accepted .idsig has the v4 layout, an accepted icon its image signature
- unpacking is bounded: no more than the catalog's size is ever produced, in bounded time
- only Refused stops it, any other exception is recorded.
"""
import gzip
import hashlib
import io
import os
from pathlib import Path
import sys
import tempfile
import zlib

import atheris

with atheris.instrument_imports():
    import fuzzlib
    import seeds
mirror = fuzzlib.load('grapheneos_mirror', 'grapheneos-mirror.py')
TMP = Path(tempfile.mkdtemp(prefix='fuzz-files-'))
FILE = TMP / 'file'

APK = b'PK\x03\x04 a stand-in APK body ' * 40
BR = b'brotli stand-in bytes'
REFS = [
    ('apk', (hashlib.sha256(APK).hexdigest(), len(APK), len(gzip.compress(APK, mtime=0))), gzip.compress(APK, mtime=0)),
    ('apk', (hashlib.sha256(b'').hexdigest(), 0, 20), gzip.compress(b'', mtime=0)),
    ('br', (len(BR), hashlib.sha256(BR).hexdigest()), BR),
    ('ina', (len(BR), hashlib.sha256(BR).hexdigest()), BR),
    ('idsig', (len(seeds.idsig()), hashlib.sha256(seeds.idsig()).hexdigest()), seeds.idsig()),
    ('idsig', (), seeds.idsig()),
    ('icon', ('webp',), seeds.webp()),
    ('icon', ('png', len(seeds.png()), hashlib.sha256(seeds.png()).hexdigest()), seeds.png()),
]


def gunzip_bounded(data, limit):
    out = bytearray()
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
        while block := f.read(65536):
            out += block
            if len(out) > limit:
                return None
    return bytes(out)


def TestOneInput(data):
    if not data:
        return
    kind, expected, original = REFS[data[0] % len(REFS)]
    body = data[1:]
    FILE.write_bytes(body)
    try:
        fuzzlib.guarded(5, mirror.check, str(FILE), kind, expected)
    except mirror.Refused:
        return
    except fuzzlib.Slow:
        fuzzlib.record('check slow ' + kind, data)
        return
    except (EOFError, zlib.error, gzip.BadGzipFile) as error:
        # Fails the run without Refused: the unit fails and nothing is published.
        fuzzlib.record('gzip error not Refused ' + type(error).__name__, data, repr(error))
        return
    except Exception as error:
        fuzzlib.record('check raised ' + fuzzlib.where(error), data, repr(error))
        return
    if kind == 'apk':
        try:
            content = gunzip_bounded(body, expected[1] + 1)
        except Exception:
            content = None
        if content is None or hashlib.sha256(content).hexdigest() != expected[0]:
            fuzzlib.record('accepted gzip that does not unpack to the APK', data)
    elif kind in ('br', 'ina') or (kind == 'idsig' and expected):
        if body != original:
            fuzzlib.record('accepted other bytes ' + kind, data)
    elif kind == 'icon' and len(expected) > 1 and body != original:
        fuzzlib.record('accepted other icon bytes', data)


def write_seeds(directory):
    os.makedirs(directory, exist_ok=True)
    for i, (_kind, _expected, original) in enumerate(REFS):
        (Path(directory) / f'seed-{i}').write_bytes(bytes([i]) + original)
    # A gzip with two members and one with trailing bytes.
    (Path(directory) / 'seed-members').write_bytes(bytes([0]) + gzip.compress(APK[:100], mtime=0)
                                                   + gzip.compress(APK[100:], mtime=0))


if __name__ == '__main__':
    if sys.argv[1:2] == ['seeds']:
        write_seeds(sys.argv[2])
    else:
        atheris.instrument_all()
        atheris.Setup(sys.argv, TestOneInput)
        atheris.Fuzz()
