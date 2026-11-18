"""compress-apks and process-static: a failed compression stops the script and leaves no compressed file.

brotli and zopfli are stand-ins on PATH. Needs GNU parallel, flock and rsync.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
FAKE = {
    # brotli --suffix=.br.tmp FILE, or brotli FILE
    'brotli': '#!/bin/sh\n[ -n "$FAIL" ] && exit 1\nif [ "$1" = --suffix=.br.tmp ]; then cp "$2" "$2.br.tmp"; else cp "$1" "$1.br"; fi\n',
    # zopfli -c FILE, or zopfli FILE
    'zopfli': '#!/bin/sh\n[ -n "$FAIL" ] && exit 1\nif [ "$1" = -c ]; then cat "$2"; else cp "$1" "$1.gz"; fi\n',
}


@unittest.skipUnless(all(shutil.which(t) for t in ('parallel', 'flock', 'rsync')), 'needs GNU parallel, flock and rsync')
class CompressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='apps-compress-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir()
        for name, text in FAKE.items():
            (bin_dir / name).write_text(text)
            (bin_dir / name).chmod(0o755)
        self.work = self.tmp / 'work'
        self.version = self.work / 'apps/packages/app.example/1'
        self.version.mkdir(parents=True)
        (self.version / 'base.apk').write_bytes(b'apk')
        self.env = dict(os.environ, PATH=str(bin_dir) + ':' + os.environ['PATH'])

    def run_script(self, name, fail=False):
        env = dict(self.env, FAIL='1') if fail else self.env
        return subprocess.run([REPO / name], cwd=self.work, env=env, capture_output=True)

    def test_compress_apks_stops_on_a_failed_compression(self):
        result = self.run_script('compress-apks', fail=True)
        self.assertNotEqual(result.returncode, 0)
        # A partial .tmp may stay. The next run removes it.
        self.assertEqual(sorted(n for n in os.listdir(self.version) if not n.endswith('.tmp')), ['base.apk'])

    def test_compress_apks_names_with_spaces_and_globs(self):
        for name in ('split one.apk', 'split*.apk'):
            (self.version / name).write_bytes(name.encode())
        (self.version / 'split').write_bytes(b'unrelated')
        result = self.run_script('compress-apks')
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ('base.apk', 'split one.apk', 'split*.apk'):
            self.assertEqual((self.version / (name + '.br')).read_bytes(), (self.version / name).read_bytes())
            self.assertEqual((self.version / (name + '.gz')).read_bytes(), (self.version / name).read_bytes())
        self.assertEqual((self.version / 'split').read_bytes(), b'unrelated')
        self.assertEqual(len(os.listdir(self.version)), 10)

    def test_process_static_stops_on_a_failed_compression(self):
        (self.work / 'static').mkdir()
        (self.work / 'static/favicon.svg').write_text('<svg/>')
        result = self.run_script('process-static', fail=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sorted(os.listdir(self.work / 'static-tmp')), ['favicon.svg', 'packages'])


if __name__ == '__main__':
    unittest.main()
