"""import-apks.py: the package name and version from aapt2 cannot place a file outside apps/packages.

aapt2 is a stand-in on PATH that prints the badging line given in BADGING.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
AAPT2 = '#!/bin/sh\nprintf "%s\\n" "$BADGING"\n'


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='apps-import-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir()
        (bin_dir / 'aapt2').write_text(AAPT2)
        (bin_dir / 'aapt2').chmod(0o755)
        self.work = self.tmp / 'work'
        (self.work / 'apps/packages').mkdir(parents=True)
        self.apk = self.tmp / 'in' / 'app.apk'
        self.apk.parent.mkdir()
        self.apk.write_bytes(b'apk')
        self.path = str(bin_dir) + ':' + os.environ['PATH']

    def run_import(self, name, code, split=''):
        badging = f"package: name='{name}' versionCode='{code}' versionName='1'{split}"
        env = dict(os.environ, PATH=self.path, BADGING=badging)
        return subprocess.run([sys.executable, REPO / 'import-apks.py', self.apk], cwd=self.work, env=env,
                              capture_output=True)

    def files(self):
        return sorted(str(p.relative_to(self.tmp)) for p in self.tmp.rglob('*') if p.is_file())

    def test_our_build_is_imported(self):
        result = self.run_import('de.diamaneos.auditor', '37')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.work / 'apps/packages/de.diamaneos.auditor/37/base.apk').read_bytes(), b'apk')

    def test_unsafe_names_and_versions_are_refused(self):
        before = self.files()
        for name, code in (('../escape', '37'), ('/tmp/abs', '37'), ('a/b', '37'), ('..', '37'),
                           ('de.diamaneos.auditor', '../1'), ('de.diamaneos.auditor', '1/2'), ('de.diamaneos.auditor', '')):
            with self.subTest(name=name, code=code):
                result = self.run_import(name, code)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.files(), before)


if __name__ == '__main__':
    unittest.main()
