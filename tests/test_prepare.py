"""prepare.py: our catalog's work tree holds only our packages, and --check refuses anything else."""
import base64
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
            'de.diamaneos.auditor': ['427bfd360586b829475f37abffd2548d93db3618e45c994de416469ef04bc2ec']})

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
            if 'isTopLevel' in p:
                packages[n]['isTopLevel'] = p['isTopLevel']
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
                         ['app.grapheneos.apps', 'app.grapheneos.camera', 'de.diamaneos.auditor'])

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
