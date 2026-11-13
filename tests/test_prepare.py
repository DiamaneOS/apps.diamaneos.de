"""prepare.py: our catalog's work tree holds only our packages, and --check refuses anything else."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tests'))
import test_grapheneos_mirror as t  # noqa: E402  (test key and signify stand-in)


def load():
    spec = importlib.util.spec_from_file_location('prepare', REPO / 'prepare.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.prepare = load()
        self.work = Path(tempfile.mkdtemp(prefix='apps-prepare-'))
        self.addCleanup(shutil.rmtree, self.work)
        fake = self.work / 'signify-openbsd'
        fake.write_text(t.SIGNIFY.format(python=sys.executable, tests=str(REPO / 'tests')))
        fake.chmod(0o755)
        self.prepare.SIGNIFY = str(fake)
        self.copy_icons()
        self.key = self.work / 'apps.0.pub'
        self.key.write_text('untrusted comment: test key\n'
                            + base64.b64encode(b'Ed' + t.KEYNUM + t.ed25519.public_key(t.SECRET)).decode() + '\n')

    def test_inventory_is_our_apps_with_their_release_signers(self):
        inventory = self.prepare.load_inventory()
        self.assertEqual({n: p['signatures'] for n, p in inventory.items()}, {
            'app.grapheneos.apps': ['559ffb104edd9386a39d512063cb7458c5ec0e29c9b52a91068ce950dd768a47'],
            'app.grapheneos.camera': ['285a091a913f1485ce16f280f06b2609dc1af6cca786e45b6f5356aa7e86fa61'],
            'de.diamaneos.camera.processor': ['285a091a913f1485ce16f280f06b2609dc1af6cca786e45b6f5356aa7e86fa61'],
            'de.diamaneos.auditor': ['427bfd360586b829475f37abffd2548d93db3618e45c994de416469ef04bc2ec'],
            'com.fps.camera': ['228b9b34992235ff4efa72f771f79a48ca8db679920fcfd8ae8fe3e25a7a4852']})

    def test_prepare_drops_other_packages_and_keeps_versions(self):
        (self.work / 'apps/packages/app.vanadium.browser/1').mkdir(parents=True)
        (self.work / 'apps/packages/app.grapheneos.camera/9304').mkdir(parents=True)
        self.prepare.prepare(str(self.work))
        self.assertEqual(sorted(os.listdir(self.work / 'apps/packages')), sorted(self.prepare.load_inventory()))
        self.assertTrue((self.work / 'apps/packages/app.grapheneos.camera/9304').is_dir())
        self.assertTrue((self.work / 'generate.py').is_file())

    def write(self, packages, secret=t.SECRET, time=1_792_600_000):
        (self.work / 'apps').mkdir(exist_ok=True)
        body = json.dumps({'time': time, 'packages': packages}).encode()
        signature = base64.b64encode(b'Ed' + t.KEYNUM + t.ed25519.sign(secret, body))
        (self.work / 'apps/metadata.1.0.sjson').write_bytes(body + b'\n' + signature + b'\n')
        # The unsigned copy is not what phones read.
        (self.work / 'apps/metadata.1.json').write_text(json.dumps({'time': 1, 'packages': self.ours()}))

    def ours(self):
        """Our catalog as generate.py writes it. The icons are those prepare() copies."""
        packages = {}
        for n, p in self.prepare.load_inventory().items():
            packages[n] = {'source': 'DiamaneOS', 'signatures': p['signatures'], 'variants': {}}
            for key in ('isTopLevel', 'group', 'deps'):
                if key in p:
                    packages[n][key] = p[key]
            if (REPO / 'apps/packages' / n / 'icon.webp').is_file():
                packages[n]['iconType'] = 'webp'
        return packages

    def copy_icons(self):
        for icon in (REPO / 'apps/packages').glob('*/icon.webp'):
            target = self.work / icon.relative_to(REPO)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(icon, target)

    def test_every_app_on_the_main_screen_has_an_icon(self):
        self.assertEqual(sorted(n for n, p in self.ours().items() if 'iconType' in p),
                         ['app.grapheneos.apps', 'app.grapheneos.camera', 'com.fps.camera', 'de.diamaneos.auditor'])

    def test_check_refuses_missing_or_unusable_icons(self):
        icon = self.work / 'apps/packages/de.diamaneos.auditor/icon.webp'
        for change in ('no icon', 'missing', 'png', 'not webp', 'too large'):
            self.copy_icons()
            packages = self.ours()
            if change == 'no icon':
                del packages['de.diamaneos.auditor']['iconType']
            elif change == 'missing':
                icon.unlink()
            elif change == 'png':
                packages['de.diamaneos.auditor']['iconType'] = 'png'
            elif change == 'not webp':
                icon.write_bytes(b'\x89PNG\r\n\x1a\n' + bytes(32))
            else:
                icon.write_bytes(icon.read_bytes()[:12] + bytes(1024 * 1024))
            self.write(packages)
            with self.assertRaises(SystemExit, msg=change):
                self.prepare.check(str(self.work), str(self.key))
        # An app not on the main screen needs none.
        self.copy_icons()
        packages = self.ours()
        self.assertNotIn('iconType', packages['de.diamaneos.camera.processor'])
        self.write(packages)
        self.prepare.check(str(self.work), str(self.key))

    def test_check_accepts_our_catalog(self):
        self.write(self.ours())
        self.prepare.check(str(self.work), str(self.key))

    def test_camera_and_its_processor_stay_linked(self):
        # Camera takes a newer CameraProcessor in its install, both in one group, CameraProcessor names nothing.
        inventory = self.prepare.load_inventory()
        self.assertEqual(inventory['app.grapheneos.camera']['group'], 'camera')
        self.assertEqual(inventory['app.grapheneos.camera']['deps'], ['de.diamaneos.camera.processor'])
        self.assertEqual(inventory['de.diamaneos.camera.processor']['group'], 'camera')
        self.assertNotIn('deps', inventory['de.diamaneos.camera.processor'])
        version = {'apks': ['base.apk'], 'label': 'Camera'}
        changes = [
            ('app.grapheneos.camera', lambda p: p.pop('deps')),
            ('app.grapheneos.camera', lambda p: p.update(deps=['de.diamaneos.camera.processor 3'])),
            ('app.grapheneos.camera', lambda p: p.update(deps2=['de.diamaneos.camera.processor'])),
            ('app.grapheneos.camera', lambda p: p.update(group='other')),
            ('app.grapheneos.camera', lambda p: p['variants'].update({'9310': dict(version, deps=[])})),
            ('de.diamaneos.camera.processor', lambda p: p.pop('group')),
            ('de.diamaneos.camera.processor', lambda p: p.update(deps=['app.grapheneos.camera'])),
            ('de.diamaneos.camera.processor', lambda p: p['variants'].update({'2': dict(version, deps2=[])})),
        ]
        for name, change in changes:
            packages = self.ours()
            change(packages[name])
            self.write(packages)
            with self.assertRaises(SystemExit, msg=name):
                self.prepare.check(str(self.work), str(self.key))
        packages = self.ours()
        del packages['de.diamaneos.camera.processor']
        self.write(packages)
        with self.assertRaises(SystemExit):
            self.prepare.check(str(self.work), str(self.key))

    def test_check_requires_a_label_in_each_version(self):
        version = {'apks': ['base.apk'], 'label': 'Camera processing'}
        for label in (None, '', ' ', 1):
            packages = self.ours()
            packages['app.grapheneos.apps']['variants'] = {'3605': dict(version, label='App Store')}
            packages['de.diamaneos.camera.processor']['variants'] = {'1': dict(version, label=label)}
            if label is None:
                del packages['de.diamaneos.camera.processor']['variants']['1']['label']
            self.write(packages)
            with self.assertRaises(SystemExit, msg=repr(label)):
                self.prepare.check(str(self.work), str(self.key))
        packages['de.diamaneos.camera.processor']['variants'] = {'1': version}
        self.write(packages)
        self.prepare.check(str(self.work), str(self.key))

    def test_check_refuses_a_catalog_older_than_the_app_stores_floor(self):
        self.write(self.ours(), time=self.prepare.MIN_TIME - 1)
        with self.assertRaises(SystemExit):
            self.prepare.check(str(self.work), str(self.key))
        self.write(self.ours(), time=self.prepare.MIN_TIME)
        self.prepare.check(str(self.work), str(self.key))

    def test_check_uses_only_signify_openbsd(self):
        self.assertEqual(load().SIGNIFY, '/usr/bin/signify-openbsd')

    def test_check_refuses_a_catalog_signed_by_another_key(self):
        self.write(self.ours(), secret=b'\x01' * 32)
        with self.assertRaises(SystemExit):
            self.prepare.check(str(self.work), str(self.key))

    def test_inventory_refuses_other_signers_and_grapheneos_apps(self):
        self.prepare.REPO = str(self.work / 'repo')
        shutil.copytree(REPO / 'apps/packages', self.work / 'repo/apps/packages')
        props = self.work / 'repo/apps/packages/de.diamaneos.camera.processor/common-props.toml'
        original = props.read_text()
        for text in (original.replace('285a091a', 'aaaaaaaa'), original.replace('"285a', '"' + 'bb' * 32 + '", "285a'),
                     original.replace('"285a', '"559ffb104edd9386a39d512063cb7458c5ec0e29c9b52a91068ce950dd768a47", "285a'),
                     original.replace('signatures = [', 'signatures = [] #')):
            props.write_text(text)
            with self.assertRaises(Exception, msg=text):
                self.prepare.load_inventory()
        props.write_text(original)
        self.prepare.load_inventory()
        props.parent.rename(props.parent.with_name('App.Attestation.Auditor'))
        with self.assertRaises(Exception):
            self.prepare.load_inventory()

    def test_pinned_app_has_only_its_signer_and_only_its_features(self):
        # The inventory takes one signer of the pinned lineage only for the pinned name, and ours not for it.
        self.prepare.REPO = str(self.work / 'repo')
        shutil.copytree(REPO / 'apps/packages', self.work / 'repo/apps/packages')
        pinned = self.work / 'repo/apps/packages/com.fps.camera/common-props.toml'
        original = pinned.read_text()
        first, tcl = self.prepare.PINNED['com.fps.camera'][0]
        self.assertEqual((first, tcl), ('0f00b338d27aa1cd1c4a00e8584501ffb36775a07af42e1cc394ca1ed0908470',
                                        '228b9b34992235ff4efa72f771f79a48ca8db679920fcfd8ae8fe3e25a7a4852'))
        self.assertIn('"' + tcl + '"', original)
        ours = '285a091a913f1485ce16f280f06b2609dc1af6cca786e45b6f5356aa7e86fa61'
        # One of ours, another beside it, both of the lineage, none, another spelling.
        for text in (original.replace(tcl, ours), original.replace('"' + tcl + '"', '"' + tcl + '", "' + ours + '"'),
                     original.replace('"' + tcl + '"', '"' + first + '", "' + tcl + '"'),
                     original.replace('signatures = [', 'signatures = [] #'), original.replace(tcl, tcl.upper())):
            pinned.write_text(text)
            with self.assertRaises(Exception, msg=text):
                self.prepare.load_inventory()
        # The older certificate alone is of the lineage too, for an APK it signs.
        pinned.write_text(original.replace(tcl, first))
        self.prepare.load_inventory()
        pinned.write_text(original)
        other = self.work / 'repo/apps/packages/de.diamaneos.camera.processor/common-props.toml'
        other.write_text(other.read_text().replace(ours, tcl))
        with self.assertRaises(Exception):
            self.prepare.load_inventory()
        # Each version of the pinned app lists exactly its features and the one that names its APK.
        self.prepare.REPO = str(REPO)
        version = {'apks': ['base.apk'], 'label': 'Camera'}
        generic, prefix = 'de.diamaneos.fairphone_camera', 'de.diamaneos.fairphone_camera.apk_'
        apks = {'801000114': b'the APK of one stock release', '801000115': b'the APK of the next stock release'}
        named = {}
        for code, data in apks.items():
            folder = self.work / 'apps/packages/com.fps.camera' / code
            folder.mkdir(parents=True)
            (folder / 'base.apk').write_bytes(data)
            named[code] = prefix + hashlib.sha256(data).hexdigest()[:16]
        apk = named['801000114']
        self.assertEqual(len(apk), len(prefix) + 16)
        for features in (None, [], ['FP6'], [generic, 'android.hardware.camera'], generic,
                         # Without the APK's name, only it, another APK's name, both names, its name twice.
                         [generic], [apk], [generic, named['801000115']], [generic, apk, named['801000115']], [generic, apk, apk],
                         # A third feature, the whole hash, fewer characters, upper case, a stock release, no string.
                         [generic, apk, 'android.hardware.camera'], [generic, prefix + hashlib.sha256(apks['801000114']).hexdigest()],
                         [generic, apk[:-1]], [generic, prefix + apk[len(prefix):].upper()],
                         [generic, 'de.diamaneos.fairphone_camera.stock_16_115_0'], [generic, 16]):
            packages = self.ours()
            packages['com.fps.camera']['variants'] = {'801000114': dict(version, **({} if features is None else {'features': features}))}
            self.write(packages)
            with self.assertRaises(SystemExit, msg=str(features)):
                self.prepare.check(str(self.work), str(self.key))
        for features in ([generic, apk], [apk, generic]):
            packages = self.ours()
            packages['com.fps.camera']['variants'] = {'801000114': dict(version, features=features)}
            self.write(packages)
            self.prepare.check(str(self.work), str(self.key))
        # Every version is checked against its own APK, and two versions stay side by side.
        packages = self.ours()
        packages['com.fps.camera']['variants'] = {'801000114': dict(version, features=[generic, apk]),
                                                  '801000115': dict(version, features=[generic, apk])}
        self.write(packages)
        with self.assertRaises(SystemExit):
            self.prepare.check(str(self.work), str(self.key))
        packages['com.fps.camera']['variants']['801000115'] = dict(version, features=[generic, named['801000115']])
        self.write(packages)
        self.prepare.check(str(self.work), str(self.key))
        # The check hashes the APK in the tree itself: another file under the same name, or none, is refused.
        (self.work / 'apps/packages/com.fps.camera/801000115/base.apk').write_bytes(b'another file')
        with self.assertRaises(SystemExit):
            self.prepare.check(str(self.work), str(self.key))
        (self.work / 'apps/packages/com.fps.camera/801000115/base.apk').unlink()
        with self.assertRaises(SystemExit):
            self.prepare.check(str(self.work), str(self.key))
        # The catalog's own hash of the version must be that APK's.
        del packages['com.fps.camera']['variants']['801000115']
        for hashes, accepted in (([hashlib.sha256(apks['801000114']).hexdigest()], True), (['0' * 64], False), ([], False)):
            packages['com.fps.camera']['variants']['801000114'] = dict(version, features=[generic, apk], apkHashes=hashes)
            self.write(packages)
            if accepted:
                self.prepare.check(str(self.work), str(self.key))
            else:
                with self.assertRaises(SystemExit, msg=str(hashes)):
                    self.prepare.check(str(self.work), str(self.key))

    def test_check_refuses_other_packages_and_signers(self):
        for change in ('other', 'signer', 'source', 'renamed', 'split'):
            packages = self.ours()
            if change == 'other':
                packages['app.vanadium.browser'] = {'source': 'GrapheneOS', 'signatures': ['aa' * 32]}
            elif change == 'signer':
                packages['app.grapheneos.camera']['signatures'] = ['bb' * 32]
            elif change == 'source':
                packages['de.diamaneos.auditor']['source'] = 'GrapheneOS'
            elif change == 'split':
                packages['de.diamaneos.camera.processor']['variants'] = {'2': {'apks': ['base.apk', 'split_x.apk']}}
            else:
                packages['app.grapheneos.apps']['originalPackage'] = 'org.example'
            self.write(packages)
            with self.assertRaises(SystemExit, msg=change):
                self.prepare.check(str(self.work), str(self.key))


if __name__ == '__main__':
    unittest.main()
