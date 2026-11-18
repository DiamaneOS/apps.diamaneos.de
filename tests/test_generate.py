"""generate.py: the catalog lists the hashes of the APKs whose signer this run checked.

apksigner and aapt2 are stand-ins: an APK whose bytes start with b'other' has another signer.
"""
import ast
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import types
import unittest

REPO = Path(__file__).resolve().parents[1]
OURS = '427bfd360586b829475f37abffd2548d93db3618e45c994de416469ef04bc2ec'
OTHER = 'ab' * 32
PKG = 'de.diamaneos.auditor'


def load():
    spec = importlib.util.spec_from_file_location('generate', REPO / 'generate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_optimized():
    """generate.py as python3 -O runs it, without its assert statements."""
    module = types.ModuleType('generate')
    source = (REPO / 'generate.py').read_text()
    exec(compile(source, str(REPO / 'generate.py'), 'exec', optimize=1), module.__dict__)
    return module


class GenerateTests(unittest.TestCase):
    def setUp(self):
        self.generate = load()
        self.root = Path(tempfile.mkdtemp(prefix='apps-generate-'))
        self.addCleanup(shutil.rmtree, self.root)
        self.version = self.root / '37'
        self.version.mkdir()
        (self.version / 'channel.toml').write_text('channel = "stable"\n')

        def check_output(argv, *args, **kwargs):
            data = Path(argv[-1]).read_bytes()
            if argv[0] == 'apksigner':
                digest = OTHER if data.startswith(b'other') else OURS
                return ('V2 Signer: certificate SHA-256 digest: ' + digest + '\n').encode()
            split = " split='config.x'" if not argv[-1].endswith('base.apk') else ''
            return (f"package: name='{PKG}' versionCode='37' versionName='37'{split}\n"
                    "minSdkVersion:'37'\napplication-label:'Auditor'\n").encode()
        self.generate.subprocess = types.SimpleNamespace(check_output=check_output)

    def apk(self, name, data):
        path = self.version / name
        path.write_bytes(data)
        for suffix in ('.gz', '.br'):
            (self.version / (name + suffix)).write_bytes(b'compressed ' + data)
            os.utime(self.version / (name + suffix), ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns))

    def process(self):
        return self.generate.process_pkg_version(str(self.root), PKG, [OURS], '37')

    def test_catalog_lists_the_checked_apk_and_not_a_cached_hash(self):
        self.apk('base.apk', b'our build')
        _, props = self.process()
        self.assertEqual(props['apkHashes'], [hashlib.sha256(b'our build').hexdigest()])
        # Another APK under the same name, with the hash file of the first one.
        self.apk('base.apk', b'our next build')
        with self.assertRaisesRegex(Exception, 'hash'):
            self.process()

    def test_every_run_checks_the_signer_of_each_split(self):
        self.apk('base.apk', b'our build')
        self.apk('split_config.arm64_v8a.apk', b'our split')
        self.process()
        self.apk('split_config.arm64_v8a.apk', b'other split')
        (self.version / 'split_config.arm64_v8a.apk.sha256').write_text(hashlib.sha256(b'other split').hexdigest())
        with self.assertRaisesRegex(Exception, 'signature mismatch'):
            self.process()


class ChecksTests(unittest.TestCase):
    """Each check stops the run under python3 -O too."""

    def setUp(self):
        self.generate = load_optimized()
        self.root = Path(tempfile.mkdtemp(prefix='apps-generate-'))
        self.addCleanup(shutil.rmtree, self.root)
        self.version = self.root / '37'
        self.version.mkdir()
        (self.version / 'channel.toml').write_text('channel = "stable"\n')
        self.first = f"package: name='{PKG}' versionCode='37' versionName='37'"
        self.lines = ["minSdkVersion:'37'", "application-label:'Auditor'"]

        def check_output(argv, *args, **kwargs):
            if argv[0] == 'apksigner':
                return ('V2 Signer: certificate SHA-256 digest: ' + OURS + '\n').encode()
            return '\n'.join([self.first, *self.lines, '']).encode()
        self.generate.subprocess = types.SimpleNamespace(check_output=check_output)
        path = self.version / 'base.apk'
        path.write_bytes(b'our build')
        for suffix in ('.gz', '.br'):
            (self.version / ('base.apk' + suffix)).write_bytes(b'compressed')
            os.utime(self.version / ('base.apk' + suffix), ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns))

    def process(self):
        return self.generate.process_pkg_version(str(self.root), PKG, [OURS], '37')

    def test_no_assert_statements(self):
        tree = ast.parse((REPO / 'generate.py').read_text())
        self.assertEqual([node.lineno for node in ast.walk(tree) if isinstance(node, ast.Assert)], [])

    def test_the_version_passes(self):
        self.assertEqual(self.process()[1]['channel'], 'stable')

    def test_other_version_code_or_package_name(self):
        for first in (f"package: name='{PKG}' versionCode='38' versionName='37'",
                      "package: name='de.diamaneos.other' versionCode='37' versionName='37'"):
            with self.subTest(first=first):
                self.first = first
                with self.assertRaisesRegex(Exception, 'is not its directory'):
                    self.process()

    def test_unknown_abi(self):
        self.lines.append("native-code: 'mips'")
        with self.assertRaisesRegex(Exception, 'unknown ABI'):
            self.process()

    def test_no_min_sdk(self):
        self.lines.remove("minSdkVersion:'37'")
        with self.assertRaisesRegex(Exception, 'no minSdkVersion'):
            self.process()

    def test_unknown_or_missing_channel(self):
        for channel in ('channel = "nightly"\n', ''):
            with self.subTest(channel=channel):
                (self.version / 'channel.toml').write_text(channel)
                with self.assertRaisesRegex(Exception, 'no known channel'):
                    self.process()

    def test_compressed_file_from_another_apk(self):
        os.utime(self.version / 'base.apk.br', ns=(0, 0))
        with self.assertRaisesRegex(Exception, 'not made from this APK'):
            self.process()


class DeltaSourceTests(unittest.TestCase):
    def setUp(self):
        self.generate = load()
        self.groups = []
        self.generate.handle_deltas_group = lambda path, name, dst, srcs: self.groups.append(
            (dst['versionCode'], [s['versionCode'] for s in srcs]))
        self.generate.SINGLE_THREAD = True

    def deltas(self, name, codes, dsts):
        variants = {c: {'versionCode': c} for c in codes}
        self.generate.process_deltas('unused', name, set(dsts), variants)
        return self.groups

    def test_no_delta_from_app_store_3701(self):
        # 3701 reads no deltas: 3704 takes 3703 and 3702, 3702 none.
        self.assertEqual(self.deltas('app.grapheneos.apps', [3701, 3702, 3703, 3704], [3704, 3702]),
                         [(3704, [3703, 3702])])
        self.groups.clear()
        self.assertEqual(self.deltas('app.grapheneos.apps', [3701, 3703], [3703]), [])

    def test_a_label_in_the_common_props_replaces_each_version_s_label(self):
        common = {'signatures': ['x'], 'label': 'Fairphone Camera'}
        variants = {'801000114': {'label': 'Camera', 'versionName': 'a'}, '801000115': {'label': 'Camera'}}
        self.generate.replace_label(common, variants)
        self.assertEqual(common, {'signatures': ['x']})
        self.assertEqual(variants, {'801000114': {'label': 'Fairphone Camera', 'versionName': 'a'}, '801000115': {'label': 'Fairphone Camera'}})
        # Without one, each version keeps the label of its APK.
        common, variants = {'signatures': ['x']}, {'9311': {'label': 'Camera'}}
        self.generate.replace_label(common, variants)
        self.assertEqual((common, variants), ({'signatures': ['x']}, {'9311': {'label': 'Camera'}}))

    def test_other_packages_keep_their_two_sources(self):
        self.assertEqual(self.deltas('app.grapheneos.camera', [3701, 9309, 9310], [9310]), [(9310, [9309, 3701])])


if __name__ == '__main__':
    unittest.main()
