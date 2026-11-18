"""Valid structures the fuzz targets start from, made here with throwaway data."""
import gzip
import hashlib
import json
import struct


def idsig():
    hashing, signing = b'h' * 40, b's' * 60
    return struct.pack('<i', 2) + struct.pack('<i', len(hashing)) + hashing + struct.pack('<i', len(signing)) + signing


def webp():
    return b'RIFF\x10\x00\x00\x00WEBPVP8 ' + b'\x00' * 8


def png():
    return b'\x89PNG\r\n\x1a\n' + b'\x00' * 16


class Catalog:
    """A catalog in the mirrored format and the files it lists, as the mirror fetches them."""

    def __init__(self, time=1_780_000_000):
        self.files, self.packages, self.time = {}, {}, time

    def apk(self, name, code, content, abis=None, v4=True, apk='base.apk', icon=None, **extra):
        gz = gzip.compress(content, mtime=0)
        br = b'brotli ' + content
        path = f'packages/{name}/{code}/{apk}'
        self.files[path + '.gz'] = gz
        self.files[path + '.br'] = br
        package = self.packages.setdefault(name, {'signatures': ['aa' * 32], 'source': 'GrapheneOS',
                                                  'variants': {}})
        variant = package['variants'].setdefault(str(code), {
            'apks': [], 'apkHashes': [], 'apkSizes': [], 'apkGzSizes': [], 'apkBrSizes': [], 'apkBrHashes': [],
            'hasV4Signatures': v4, 'label': name, 'channel': 'stable', 'versionCode': code, **extra})
        variant['apks'].append(apk)
        variant['apkHashes'].append(hashlib.sha256(content).hexdigest())
        variant['apkSizes'].append(len(content))
        variant['apkGzSizes'].append(len(gz))
        variant['apkBrSizes'].append(len(br))
        variant['apkBrHashes'].append(hashlib.sha256(br).hexdigest())
        if v4:
            self.files[path + '.idsig'] = idsig()
            variant.setdefault('v4SignatureSizes', []).append(len(idsig()))
            variant.setdefault('v4SignatureHashes', []).append(hashlib.sha256(idsig()).hexdigest())
        if abis:
            variant['abis'] = abis
        if icon:
            data = webp() if icon == 'webp' else png()
            self.files[f'packages/{name}/icon.{icon}'] = data
            package.update(iconType=icon, iconSize=len(data), iconSha256=hashlib.sha256(data).hexdigest())
        return variant

    def delta(self, name, code, sources, apk_count=1):
        variant = self.packages[name]['variants'][str(code)]
        variant['availableDeltaVersions'] = list(sources)
        for column in ('apkDeltaSizes', 'apkDeltaHashes', 'apkDeltaSrcHashes'):
            variant[column] = []
        for i in range(apk_count):
            apk = variant['apks'][i]
            for source, content in sources.items():
                if content is None:
                    variant['apkDeltaSizes'].append(0)
                    variant['apkDeltaHashes'].append('')
                    variant['apkDeltaSrcHashes'].append('')
                    continue
                self.files[f'packages/{name}/{code}/{apk}.{source}.ina'] = content
                variant['apkDeltaSizes'].append(len(content))
                variant['apkDeltaHashes'].append(hashlib.sha256(content).hexdigest())
                variant['apkDeltaSrcHashes'].append(hashlib.sha256(b'source %d' % source).hexdigest())

    def body(self):
        return json.dumps({'time': self.time, 'packages': self.packages, 'fsVerityCerts': {}},
                          separators=(',', ':')).encode()


def catalogs():
    """A few catalogs covering the fields the mirror reads."""
    result = []
    c = Catalog()
    c.apk('app.vanadium.browser', 10, b'browser apk 10', icon='webp')
    c.apk('app.grapheneos.pdfviewer', 20, b'pdf apk 20', abis=['arm64-v8a', 'x86_64'], icon='png')
    c.apk('app.grapheneos.pdfviewer', 21, b'pdf apk 21')
    c.apk('app.grapheneos.pdfviewer', 21, b'pdf split 21', apk='split_config.arm64_v8a.apk')
    c.delta('app.grapheneos.pdfviewer', 21, {20: b'delta 20 to 21', 19: None}, apk_count=2)
    c.apk('app.grapheneos.info', 5, b'info apk')
    c.apk('app.grapheneos.camera', 7, b'their camera')
    c.apk('com.example.x86only', 3, b'x86 only', abis=['x86_64'])
    result.append(c)
    d = Catalog(time=1_780_000_100)
    d.apk('app.vanadium.browser', 11, b'browser apk 11', v4=False, icon='webp')
    d.packages['app.attestation.auditor'] = {'source': 'GrapheneOS', 'variants': {}}
    d.packages['com.example.renamed'] = {'source': 'GrapheneOS', 'originalPackage': 'de.diamaneos.thing',
                                         'variants': {}}
    result.append(d)
    return result
