"""generate.py: the catalog lists the hashes of the APKs whose signer this run checked.

apksigner and aapt2 are stand-ins: an APK whose bytes start with b'other' has another signer.
"""
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
