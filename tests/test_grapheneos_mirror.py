"""grapheneos-mirror.py against a local stand-in for apps.grapheneos.org with a test catalog key.

signify is replaced by a stand-in that checks real Ed25519 signatures (RFC 8032 reference code).
Run with Python 3.11 or newer: python3 -m unittest discover -s tests
"""
import base64
import contextlib
import gzip
import hashlib
import http.server
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import threading
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
import ed25519_reference as ed25519  # noqa: E402

SECRET = hashlib.sha256(b'DiamaneOS mirror test key, never a real one').digest()
KEYNUM = bytes.fromhex('0123456789abcdef')
SIGNIFY = '''#!{python}
import base64, sys
sys.path.insert(0, {tests!r})
import ed25519_reference
args = sys.argv[1:]
assert args[:2] == ['-V', '-q']
pub, msg, sig = (args[args.index(flag) + 1] for flag in ('-p', '-m', '-x'))
key = base64.b64decode(open(pub).read().splitlines()[1])
signature = base64.b64decode(open(sig).read().splitlines()[1])
data = open(msg, 'rb').read()
ok = key[:2] == signature[:2] == b'Ed' and key[2:10] == signature[2:10]
sys.exit(0 if ok and ed25519_reference.verify(key[10:], data, signature[10:]) else 1)
'''


def idsig():
    hashing, signing = b'h' * 40, b's' * 60
    return struct.pack('<i', 2) + struct.pack('<i', len(hashing)) + hashing + struct.pack('<i', len(signing)) + signing


def webp():
    return b'RIFF\x10\x00\x00\x00WEBPVP8 ' + b'\x00' * 8


class Upstream:
    """Files served as apps.grapheneos.org and the catalog built from them."""

    def __init__(self):
        self.files, self.packages, self.time = {}, {}, 1_780_000_000
        self.redirect = set()
        # Paths whose connection drops before the whole file is sent.
        self.truncated = set()

    def apk(self, name, code, content, abis=None, v4=True, apk='base.apk', **extra):
        gz = gzip.compress(content, mtime=0)
        path = f'packages/{name}/{code}/{apk}'
        self.files[path + '.gz'] = gz
        if v4:
            self.files[path + '.idsig'] = idsig()
        variant = {'apks': [apk], 'apkHashes': [hashlib.sha256(content).hexdigest()],
                   'apkSizes': [len(content)], 'apkGzSizes': [len(gz)], 'apkBrSizes': [len(gz)],
                   'hasV4Signatures': v4, 'label': name, 'channel': 'stable', **extra}
        if abis:
            variant['abis'] = abis
        package = self.packages.setdefault(name, {'signatures': ['aa' * 32], 'source': 'GrapheneOS', 'variants': {}})
        package['variants'][str(code)] = variant
        return package

    def catalog(self, secret=SECRET):
        body = json.dumps({'time': self.time, 'packages': self.packages, 'fsVerityCerts': {}},
                          separators=(',', ':')).encode()
        signature = base64.b64encode(b'Ed' + KEYNUM + ed25519.sign(secret, body))
        self.files['metadata.1.0.sjson'] = body + b'\n' + signature + b'\n'
        return self.files['metadata.1.0.sjson']


class MirrorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='grapheneos-mirror-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir()
        fake = bin_dir / 'signify-openbsd'
        fake.write_text(SIGNIFY.format(python=sys.executable, tests=str(HERE)))
        fake.chmod(0o755)
        key = self.tmp / 'test.pub'
        key.write_text('untrusted comment: test key\n'
                       + base64.b64encode(b'Ed' + KEYNUM + ed25519.public_key(SECRET)).decode() + '\n')
        spec = importlib.util.spec_from_file_location('grapheneos_mirror', REPO / 'grapheneos-mirror.py')
        self.mirror = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mirror)
        self.assertEqual(self.mirror.SIGNIFY, '/usr/bin/signify-openbsd')
        self.mirror.SIGNIFY = str(fake)
        self.mirror.KEY = str(key)
        self.upstream = Upstream()
        upstream = self.upstream

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                path = self.path.lstrip('/')
                if path in upstream.redirect:
                    self.send_response(302)
                    self.send_header('Location', '/elsewhere')
                    self.end_headers()
                    return
                data = upstream.files.get(path)
                self.send_response(200 if data is not None else 404)
                # As GrapheneOS's server, each file with its length.
                if data is not None:
                    self.send_header('Content-Length', str(len(data) + (100 if path in upstream.truncated else 0)))
                self.end_headers()
                if data is not None:
                    self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.mirror.UPSTREAM = f'http://127.0.0.1:{self.server.server_port}'
        self.root, self.state = self.tmp / 'root', self.tmp / 'state'
        self.root.mkdir()

    def standard(self):
        u = self.upstream
        u.apk('app.vanadium.browser', 1, b'browser arm', abis=['arm64-v8a'])
        u.packages['app.vanadium.browser']['iconType'] = 'webp'
        u.packages['app.vanadium.browser']['originalPackage'] = 'org.chromium.chrome'
        u.files['packages/app.vanadium.browser/icon.webp'] = webp()
        u.apk('app.vanadium.browser', 2, b'browser x86', abis=['x86_64'])
        u.apk('com.google.android.gms', 5, b'gms', v4=False)
        u.packages['com.google.android.gms']['source'] = 'Google'
        u.apk('app.grapheneos.info', 7, b'info')
        u.apk('app.attestation.auditor', 92, b'auditor')
        u.apk('app.grapheneos.apps', 36, b'their app store')
        u.apk('app.example.renamed', 1, b'renamed')
        u.packages['app.example.renamed']['originalPackage'] = 'app.grapheneos.camera'
        u.apk('app.example.label', 1, b'label')
        u.packages['app.example.label']['source'] = 'DiamaneOS'
        u.apk('de.diamaneos.future', 1, b'ours later')

    def run_mirror(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.mirror.mirror(str(self.root), str(self.state))
        return out.getvalue()

    def files(self):
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*') if p.is_file())

    def test_publishes_catalog_unchanged_with_only_the_app_stores_files(self):
        self.standard()
        catalog = self.upstream.catalog()
        output = self.run_mirror()
        self.assertEqual((self.root / 'metadata.1.0.sjson').read_bytes(), catalog)
        self.assertEqual(self.files(), ['metadata.1.0.sjson',
                                        'packages/app.vanadium.browser/1/base.apk.gz',
                                        'packages/app.vanadium.browser/1/base.apk.idsig',
                                        'packages/app.vanadium.browser/icon.webp',
                                        'packages/com.google.android.gms/5/base.apk.gz'])
        self.assertEqual(self.upstream.files['packages/app.vanadium.browser/1/base.apk.gz'],
                         (self.root / 'packages/app.vanadium.browser/1/base.apk.gz').read_bytes())
        self.assertNotIn("GrapheneOS's catalog:", output)
        # Nothing new: no APK is fetched again.
        self.assertIn(' 0 MB fetched, 0 removed', self.run_mirror())

    def test_wrong_signature_publishes_nothing(self):
        self.standard()
        self.upstream.catalog(secret=hashlib.sha256(b'another key').digest())
        with self.assertRaisesRegex(self.mirror.Refused, 'signature'):
            self.run_mirror()
        self.assertEqual(self.files(), [])

    def test_tampered_catalog_publishes_nothing(self):
        self.standard()
        data = self.upstream.catalog()
        self.upstream.files['metadata.1.0.sjson'] = data.replace(b'"time":', b'"time": ', 1)
        with self.assertRaisesRegex(self.mirror.Refused, 'signature'):
            self.run_mirror()
        self.assertFalse((self.root / 'metadata.1.0.sjson').exists())

    def test_apk_not_matching_the_catalog_keeps_the_published_catalog(self):
        self.standard()
        first = self.upstream.catalog()
        self.run_mirror()
        self.upstream.time += 10
        self.upstream.apk('app.vanadium.browser', 3, b'browser new', abis=['arm64-v8a'])
        self.upstream.catalog()
        self.upstream.files['packages/app.vanadium.browser/3/base.apk.gz'] = gzip.compress(b'browser evil', mtime=0)
        with self.assertRaisesRegex(self.mirror.Refused, 'exceeds|size|does not match'):
            self.run_mirror()
        self.assertEqual((self.root / 'metadata.1.0.sjson').read_bytes(), first)
        self.assertFalse((self.root / 'packages/app.vanadium.browser/3/base.apk.gz').exists())

    def test_same_size_wrong_content_refused(self):
        self.upstream.apk('app.vanadium.config', 1, b'config A', v4=False)
        self.upstream.catalog()
        self.upstream.files['packages/app.vanadium.config/1/base.apk.gz'] = gzip.compress(b'config B', mtime=0)
        with self.assertRaisesRegex(self.mirror.Refused, 'does not match'):
            self.run_mirror()
        self.assertEqual(self.files(), [])

    def test_oversized_download_refused(self):
        self.upstream.apk('app.vanadium.config', 1, b'config', v4=False)
        self.upstream.catalog()
        gz = self.upstream.files['packages/app.vanadium.config/1/base.apk.gz']
        self.upstream.files['packages/app.vanadium.config/1/base.apk.gz'] = gz + b'\x00' * 4096
        with self.assertRaisesRegex(self.mirror.Refused, 'exceeds'):
            self.run_mirror()

    def test_older_catalog_refused(self):
        self.standard()
        self.upstream.catalog()
        self.run_mirror()
        published = (self.root / 'metadata.1.0.sjson').read_bytes()
        self.upstream.time -= 1
        self.upstream.catalog()
        with self.assertRaisesRegex(self.mirror.Refused, 'older'):
            self.run_mirror()
        self.assertEqual((self.root / 'metadata.1.0.sjson').read_bytes(), published)

    def test_previous_versions_stay_for_one_update(self):
        u = self.upstream
        u.apk('app.vanadium.config', 1, b'one', v4=False)
        u.catalog()
        self.run_mirror()
        del u.packages['app.vanadium.config']['variants']['1']
        u.apk('app.vanadium.config', 2, b'two', v4=False)
        u.time += 1
        u.catalog()
        self.run_mirror()
        self.assertIn('packages/app.vanadium.config/1/base.apk.gz', self.files())
        del u.packages['app.vanadium.config']['variants']['2']
        u.apk('app.vanadium.config', 3, b'three', v4=False)
        u.time += 1
        u.catalog()
        self.run_mirror()
        self.assertEqual(self.files(), ['metadata.1.0.sjson', 'packages/app.vanadium.config/2/base.apk.gz',
                                        'packages/app.vanadium.config/3/base.apk.gz'])

    def test_published_file_changed_under_the_same_name_refused(self):
        self.upstream.apk('app.vanadium.config', 1, b'one', v4=False)
        self.upstream.catalog()
        self.run_mirror()
        (self.state / 'verified.json').unlink()
        (self.root / 'packages/app.vanadium.config/1/base.apk.gz').write_bytes(gzip.compress(b'two', mtime=0))
        with self.assertRaisesRegex(self.mirror.Refused, 'size|does not match'):
            self.run_mirror()

    def test_package_changes_are_logged_and_still_published(self):
        self.standard()
        self.upstream.catalog()
        self.run_mirror()
        self.upstream.packages['app.vanadium.browser']['signatures'] = ['bb' * 32]
        del self.upstream.packages['com.google.android.gms']
        self.upstream.apk('app.example.new', 1, b'new', v4=False)
        self.upstream.time += 1
        catalog = self.upstream.catalog()
        output = self.run_mirror()
        self.assertIn("GrapheneOS's catalog: added app.example.new", output)
        self.assertIn("GrapheneOS's catalog: dropped com.google.android.gms", output)
        self.assertIn("GrapheneOS's catalog: other signers for app.vanadium.browser: " + 'bb' * 32, output)
        self.assertEqual((self.root / 'metadata.1.0.sjson').read_bytes(), catalog)

    def test_icons_are_not_fatal_and_fetched_only_with_a_new_catalog(self):
        self.standard()
        self.upstream.catalog()
        self.run_mirror()
        icon = self.root / 'packages/app.vanadium.browser/icon.webp'
        self.assertEqual(icon.read_bytes(), webp())
        self.upstream.files['packages/app.vanadium.browser/icon.webp'] = b'not an image at all'
        self.run_mirror()
        self.assertEqual(icon.read_bytes(), webp())
        self.upstream.time += 1
        catalog = self.upstream.catalog()
        output = self.run_mirror()
        self.assertIn('icon kept as it was: packages/app.vanadium.browser/icon.webp', output)
        self.assertEqual(icon.read_bytes(), webp())
        self.assertEqual((self.root / 'metadata.1.0.sjson').read_bytes(), catalog)
        # So does a dropped connection.
        self.upstream.files['packages/app.vanadium.browser/icon.webp'] = webp() + b'more'
        self.upstream.truncated.add('packages/app.vanadium.browser/icon.webp')
        self.upstream.time += 1
        catalog = self.upstream.catalog()
        output = self.run_mirror()
        self.assertIn('icon kept as it was: packages/app.vanadium.browser/icon.webp', output)
        self.assertEqual(icon.read_bytes(), webp())
        self.assertEqual((self.root / 'metadata.1.0.sjson').read_bytes(), catalog)
        # A missing icon or an unknown icon type only leaves the package without one.
        del self.upstream.files['packages/app.vanadium.browser/icon.webp']
        self.upstream.packages['com.google.android.gms']['iconType'] = 'svg'
        self.upstream.time += 1
        catalog = self.upstream.catalog()
        self.run_mirror()
        self.assertEqual((self.root / 'metadata.1.0.sjson').read_bytes(), catalog)

    def test_unsafe_versions_refused(self):
        for code in ('01', '\u0661', '1/../2', '-1'):
            with self.subTest(code=code):
                self.upstream.packages.clear()
                self.upstream.apk('app.vanadium.config', 1, b'one', v4=False)
                variants = self.upstream.packages['app.vanadium.config']['variants']
                variants[code] = variants.pop('1')
                self.upstream.catalog()
                with self.assertRaisesRegex(self.mirror.Refused, 'unexpected version'):
                    self.run_mirror()

    def test_unsafe_package_names_refused(self):
        for name in ('app.example/../../etc', '../app.example', 'app.example\n', 'app'):
            with self.subTest(name=name):
                self.upstream.packages.clear()
                self.upstream.packages[name] = {'signatures': ['aa' * 32], 'source': 'GrapheneOS', 'variants': {}}
                self.upstream.catalog()
                with self.assertRaisesRegex(self.mirror.Refused, 'unexpected package name'):
                    self.run_mirror()
        self.assertFalse(any(self.tmp.rglob('etc')))

    def test_redirect_refused(self):
        self.upstream.catalog()
        self.upstream.redirect.add('metadata.1.0.sjson')
        with self.assertRaisesRegex(self.mirror.Refused, 'redirect'):
            self.run_mirror()

    def test_bad_v4_signature_file_refused(self):
        self.upstream.apk('app.vanadium.config', 1, b'one')
        self.upstream.catalog()
        self.upstream.files['packages/app.vanadium.config/1/base.apk.idsig'] = b'\x02\x00\x00\x00' + b'\xff' * 12
        with self.assertRaisesRegex(self.mirror.Refused, 'v4'):
            self.run_mirror()

    def test_unsafe_names_refused(self):
        self.upstream.apk('app.vanadium.config', '1', b'one', v4=False, apk='../../x.apk')
        self.upstream.catalog()
        with self.assertRaisesRegex(self.mirror.Refused, 'unexpected APK entry'):
            self.run_mirror()

    def test_scope_matches_the_app_store(self):
        listed = self.mirror.listed
        for name in ('app.grapheneos.apps', 'app.grapheneos.camera', 'de.diamaneos.auditor',
                     'app.grapheneos.info', 'app.attestation.auditor', 'de.diamaneos.other'):
            self.assertFalse(listed(name, {'source': 'GrapheneOS'}), name)
        self.assertFalse(listed('app.example', {'originalPackage': 'app.grapheneos.camera'}))
        self.assertFalse(listed('app.example', {'source': 'DiamaneOS'}))
        for name in ('De.Diamaneos.x', 'de.diamaneos', 'App.GrapheneOS.Apps', 'APP.ATTESTATION.AUDITOR'):
            self.assertFalse(listed(name, {}), name)
        self.assertTrue(listed('de.diamaneosx.other', {}))
        self.assertTrue(listed('app.vanadium.browser', {'originalPackage': 'org.chromium.chrome'}))

    def test_scope_sets_match_the_app_store(self):
        """OURS and EXCLUDED equal Catalogs.kt in an AppStore checkout next to this one (or APPSTORE_SOURCE)."""
        source = Path(os.environ.get('APPSTORE_SOURCE', REPO.parent / 'AppStore'))
        catalogs = source / 'app/src/main/java/app/grapheneos/apps/core/Catalogs.kt'
        if not catalogs.is_file():
            self.skipTest('no AppStore checkout at ' + str(source))
        text = catalogs.read_text()
        def kotlin_set(name):
            found = re.search(r'val ' + name + r' = setOf\(([^)]*)\)', text)
            return set(re.findall(r'"([^"]+)"', found[1]))
        self.assertEqual(kotlin_set('DIAMANEOS_PACKAGES'), self.mirror.OURS)
        self.assertEqual(kotlin_set('EXCLUDED_PACKAGES'), self.mirror.EXCLUDED)
        prepare = importlib.util.spec_from_file_location('prepare', REPO / 'prepare.py')
        module = importlib.util.module_from_spec(prepare)
        prepare.loader.exec_module(module)
        self.assertEqual(kotlin_set('DIAMANEOS_SIGNERS'), module.SIGNERS)
        self.assertEqual(module.EXCLUDED, self.mirror.EXCLUDED)
        floor = re.search(r'DiamaneOS\(BuildConfig\.REPO_PUBLIC_KEY, [^)]*, ([0-9_]+)L\)', text)
        self.assertEqual(int(floor[1].replace('_', '')), module.MIN_TIME)

if __name__ == '__main__':
    unittest.main()
