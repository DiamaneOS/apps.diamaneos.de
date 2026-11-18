#!/usr/bin/env python3
"""generate.py: apksigner and aapt2 output, channel.toml and props.toml of one version, through
process_pkg_version() with stand-ins for the two tools.

Property checks on an accepted version:
- the signer is the inventory's, and apksigner names no other signer certificate
- versionCode is the directory's and the APK's
- the catalog's hashes and sizes are those of the files in the directory, one per APK
- the channel is a known one, the label a non-empty string and minSdk an integer
- channel.toml and props.toml add only their own keys, with lists of strings where they take lists.
generate.py refuses with an Exception and a message, which stops it before anything is signed. Any
other exception type is recorded.
"""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import types

import atheris

with atheris.instrument_imports():
    import fuzzlib
generate = fuzzlib.load('generate', 'generate.py')
TMP = Path(tempfile.mkdtemp(prefix='fuzz-generate-'))
OURS = '559ffb104edd9386a39d512063cb7458c5ec0e29c9b52a91068ce950dd768a47'
OTHER = 'ab' * 32
PKG = 'app.grapheneos.apps'
# apksigner verify --print-certs --verbose of build tools 37 names one signer as 'V3.0 Signer:', several as
# 'V2 Signer #1:', a key rotated for SDK ranges with its range, and a source stamp, which is no signer.
SIGNER_LINES = [
    'V2 Signer: certificate SHA-256 digest: ' + OURS,
    'V3.0 Signer: certificate SHA-256 digest: ' + OURS,
    'V1 Signer: certificate SHA-256 digest: ' + OTHER,
    'V3.1 Signer: (minSdkVersion=33, maxSdkVersion=2147483647) certificate SHA-256 digest: ' + OTHER,
    'V3.0 Signer: (minSdkVersion=24, maxSdkVersion=32) certificate SHA-256 digest: ' + OURS,
    'Signer #1 certificate SHA-256 digest: ' + OTHER,
    'V2 Signer: certificate SHA-256 digest: ' + OURS.upper(),
    'Verified using v2 scheme (APK Signature Scheme v2): true',
    'Number of signers: 1',
    'Number of signers: 2',
    'V2 Signer #1: certificate SHA-256 digest: ' + OURS,
    'V2 Signer #2: certificate SHA-256 digest: ' + OTHER,
    'Source Stamp Signer: certificate SHA-256 digest: ' + OTHER,
    'V3.0 Signer: public key SHA-256 digest: ' + OTHER,
]
BADGING_FIRST = ["package: name='{pkg}' versionCode='{code}' versionName='1.0' platformBuildVersionName='17'",
                 "package: name='{pkg}' versionCode='{code}' versionName='a=b' split='config.arm64_v8a'",
                 "package: name='other.pkg' versionCode='{code}' versionName='1'",
                 "package: name='{pkg}' versionCode='{code}0' versionName='1'"]
BADGING_LINES = ["sdkVersion:'31'", "minSdkVersion:'31'", "targetSdkVersion:'37'", "application-label:'App Store'",
                 "application-label:'It\\'s'", "application-label:'A: B'", "application: label='Manifest' icon='x'",
                 "native-code: 'arm64-v8a'", "native-code: 'mips'", "alt-native-code: 'x86_64'",
                 "application-label-de:'Laden'", "uses-permission: name='android.permission.INTERNET'"]
FROM_APK = {'versionCode', 'versionName', 'label', 'minSdk', 'maxSdk', 'abis', 'apks', 'apkHashes', 'apkSizes',
            'apkGzSizes', 'apkBrSizes', 'apkBrHashes', 'hasV4Signatures', 'v4SignatureSizes', 'v4SignatureHashes'}
TOMLS = ['channel = "stable"\n', 'channel = "alpha"\n', 'channel = "old"\n', 'channel = "nightly"\n', '',
         'versionCode = 999\n', 'apkHashes = ["00"]\n', 'channel = "beta"\nlabel = ""\n', 'minSdk = "x"\n',
         'apks = ["../x.apk"]\n', 'channel = 1\n', '[x\n', 'features = ["de.diamaneos.fairphone_camera"]\n',
         'staticDeps = ["app.grapheneos.apps >= 34"]\n', 'requiredSystemFeatures = [1]\n', 'features = "x"\n',
         'channel = "stable"\nchannel = "beta"\n']


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    code = str(fdp.ConsumeIntInRange(1, 40))
    lines = [SIGNER_LINES[fdp.ConsumeIntInRange(0, len(SIGNER_LINES) - 1)] for _ in range(fdp.ConsumeIntInRange(0, 4))]
    if fdp.ConsumeBool():
        lines.append(fdp.ConsumeUnicodeNoSurrogates(80))
    apksigner = '\n'.join(lines).encode()
    first = BADGING_FIRST[fdp.ConsumeIntInRange(0, len(BADGING_FIRST) - 1)].format(pkg=PKG, code=code)
    rest = [BADGING_LINES[fdp.ConsumeIntInRange(0, len(BADGING_LINES) - 1)] for _ in range(fdp.ConsumeIntInRange(0, 6))]
    if fdp.ConsumeBool():
        rest.append(fdp.ConsumeUnicodeNoSurrogates(60))
    badging = '\n'.join([first, *rest, '']).encode()
    channel = TOMLS[fdp.ConsumeIntInRange(0, len(TOMLS) - 1)]
    props = TOMLS[fdp.ConsumeIntInRange(0, len(TOMLS) - 1)] if fdp.ConsumeBool() else None
    content = fdp.ConsumeBytes(64) or b'apk'
    root = Path(tempfile.mkdtemp(dir=TMP))
    version = root / code
    version.mkdir()
    apk = version / 'base.apk'
    apk.write_bytes(content)
    for suffix in ('.gz', '.br'):
        (version / ('base.apk' + suffix)).write_bytes(b'compressed ' + content)
        os.utime(version / ('base.apk' + suffix), ns=(apk.stat().st_atime_ns, apk.stat().st_mtime_ns))
    (version / 'channel.toml').write_text(channel)
    if props is not None:
        (version / 'props.toml').write_text(props)

    def check_output(argv, *args, **kwargs):
        return apksigner if argv[0] == 'apksigner' else badging
    generate.subprocess = types.SimpleNamespace(check_output=check_output, call=None, run=None)
    try:
        result = generate.process_pkg_version(str(root), PKG, [OURS], code)
    except Exception as error:
        if type(error) is not Exception:
            fuzzlib.record('process_pkg_version raised ' + fuzzlib.where(error), data, repr(error))
        return
    finally:
        import shutil
        shutil.rmtree(root)
    if result is None:
        return
    _, p = result
    unrestricted = [l for l in lines if l.startswith('V') and ' Signer' in l and 'maxSdkVersion' not in l]
    if not any(l.endswith(OURS) for l in lines):
        fuzzlib.record('accepted without our signer line', data, repr(lines))
    if any(OTHER in l for l in lines if ' certificate SHA-256 digest: ' in l and not l.startswith('Source Stamp')):
        fuzzlib.record('accepted with another signer listed', data, repr(lines))
    if 'Number of signers: 2' in lines:
        fuzzlib.record('accepted with two signers counted', data, repr(lines))
    if p['versionCode'] != int(code):
        fuzzlib.record('catalog versionCode differs from the directory and APK', data, repr(p['versionCode']))
    if p.get('apkHashes') != [hashlib.sha256(content).hexdigest()] or p.get('apks') != ['base.apk']:
        fuzzlib.record('catalog hashes or APK list differ from the files', data, repr(p.get('apkHashes')))
    if p.get('channel') not in ('alpha', 'beta', 'stable'):
        fuzzlib.record('unknown channel listed', data, repr(p.get('channel')))
    if not isinstance(p.get('label'), str) or not p.get('label'):
        fuzzlib.record('version listed without a label', data)
    if not isinstance(p.get('minSdk'), int):
        fuzzlib.record('minSdk not an integer', data, repr(p.get('minSdk')))
    extra = set(p) - FROM_APK - {'channel', 'features', 'requiredSystemFeatures', 'staticDeps'}
    if extra or any(not isinstance(p[k], list) or not all(isinstance(i, str) and i for i in p[k])
                    for k in ('features', 'requiredSystemFeatures', 'staticDeps') if k in p):
        fuzzlib.record('a toml file set a key or value it may not', data, repr(sorted(extra)))


def write_seeds(directory):
    os.makedirs(directory, exist_ok=True)
    (Path(directory) / 'seed-0').write_bytes(bytes([5, 1, 0, 0, 0, 2, 1, 3, 0, 0]) + b'apk bytes')


if __name__ == '__main__':
    if sys.argv[1:2] == ['seeds']:
        write_seeds(sys.argv[2])
    else:
        atheris.instrument_all()
        atheris.Setup(sys.argv, TestOneInput)
        atheris.Fuzz()
