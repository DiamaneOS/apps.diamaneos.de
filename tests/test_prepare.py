"""prepare.py: our catalog's work tree holds only our packages, and --check refuses anything else."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]


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

    def test_inventory_is_our_three_apps_with_their_release_signers(self):
        inventory = self.prepare.load_inventory()
        self.assertEqual(set(inventory), self.prepare.OURS)
        self.assertEqual({n: p['signatures'] for n, p in inventory.items()}, {
            'app.grapheneos.apps': ['559ffb104edd9386a39d512063cb7458c5ec0e29c9b52a91068ce950dd768a47'],
            'app.grapheneos.camera': ['285a091a913f1485ce16f280f06b2609dc1af6cca786e45b6f5356aa7e86fa61'],
            'de.diamaneos.auditor': ['427bfd360586b829475f37abffd2548d93db3618e45c994de416469ef04bc2ec']})

    def test_prepare_drops_other_packages_and_keeps_versions(self):
        (self.work / 'apps/packages/app.vanadium.browser/1').mkdir(parents=True)
        (self.work / 'apps/packages/app.grapheneos.camera/9304').mkdir(parents=True)
        self.prepare.prepare(str(self.work))
        self.assertEqual(sorted(os.listdir(self.work / 'apps/packages')), sorted(self.prepare.OURS))
        self.assertTrue((self.work / 'apps/packages/app.grapheneos.camera/9304').is_dir())
        self.assertTrue((self.work / 'generate.py').is_file())

    def write(self, packages):
        (self.work / 'apps').mkdir(exist_ok=True)
        (self.work / 'apps/metadata.1.json').write_text(json.dumps({'time': 1, 'packages': packages}))

    def ours(self):
        return {n: {'source': 'DiamaneOS', 'signatures': p['signatures'], 'variants': {}}
                for n, p in self.prepare.load_inventory().items()}

    def test_check_accepts_our_catalog(self):
        self.write(self.ours())
        self.prepare.check(str(self.work))

    def test_check_refuses_other_packages_and_signers(self):
        for change in ('other', 'signer', 'source', 'renamed'):
            packages = self.ours()
            if change == 'other':
                packages['app.vanadium.browser'] = {'source': 'GrapheneOS', 'signatures': ['aa' * 32]}
            elif change == 'signer':
                packages['app.grapheneos.camera']['signatures'] = ['bb' * 32]
            elif change == 'source':
                packages['de.diamaneos.auditor']['source'] = 'GrapheneOS'
            else:
                packages['app.grapheneos.apps']['originalPackage'] = 'org.example'
            self.write(packages)
            with self.assertRaises(SystemExit, msg=change):
                self.prepare.check(str(self.work))


if __name__ == '__main__':
    unittest.main()
