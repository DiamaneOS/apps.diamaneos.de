#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

REPO = Path(__file__).resolve().parent.parent


def load():
    spec = importlib.util.spec_from_file_location('generate', REPO / 'generate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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

    def test_other_packages_keep_their_two_sources(self):
        self.assertEqual(self.deltas('app.grapheneos.camera', [3701, 9309, 9310], [9310]), [(9310, [9309, 3701])])


if __name__ == '__main__':
    unittest.main()
