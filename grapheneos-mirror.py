#!/usr/bin/env python3
"""Mirror GrapheneOS's signed app catalog and APKs unchanged, served as apps.diamaneos.de/grapheneos/.

./grapheneos-mirror.py ROOT STATE

ROOT is the served grapheneos/ directory and STATE the job's own state. It needs no key.

1. Fetches GrapheneOS's catalog, checks its signature with grapheneos-apps.0.pub (signify) and that it
   is not older than the published one or the newest one ever published (the floor in STATE).
2. Refuses a catalog that lists more files, larger files or more bytes in total than the caps, or a path
   twice. Fetches every APK the App Store may take from it for arm64-v8a: GrapheneOS's packages without ours
   and without the excluded ones, as in the App Store's Catalogs.kt. Each .gz (App Store 36) must have
   the catalog's size and unpack to the catalog's size and SHA-256. Each .br (App Store 37) must have
   the catalog's size and SHA-256, and so must each .ina (a delta from an older version) with a size
   above 0. v4 signatures and icons are checked against the catalog's size and SHA-256 where it lists
   them, and their format always. Icons are fetched again only with a new catalog, and a failed icon
   keeps the previous one. A new icon replaces the published one only after the new catalog.
3. Only then publishes the catalog bytes unchanged. Files of a replaced catalog stay for KEEP_REPLACED,
   and files that neither this catalog nor a kept one lists are removed. Packages added, dropped or with
   other signers than in the previous catalog are logged.
4. Fails after all this when GrapheneOS's catalog is older than MAX_AGE, so that monitoring alerts.
"""

import fcntl
import gzip
import hashlib
import http.client
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zlib

UPSTREAM = "https://apps.grapheneos.org"
CATALOG = "metadata.1.0.sjson"
ABI = "arm64-v8a"
HERE = os.path.dirname(os.path.abspath(__file__))
KEY = os.path.join(HERE, "grapheneos-apps.0.pub")
# Debian's OpenBSD signify. Debian's plain signify is an unrelated mail tool.
SIGNIFY = "/usr/bin/signify-openbsd"
# Our builds come from our own catalog. The App Store refuses them from GrapheneOS's.
OURS = {"app.grapheneos.apps", "app.grapheneos.camera", "de.diamaneos.auditor"}
# Info shows GrapheneOS's release news, and our Auditor replaces GrapheneOS's Auditor.
EXCLUDED = {"app.grapheneos.info", "app.attestation.auditor"}
SHA256 = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"[1-9][0-9]{0,18}")
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+")
APK = re.compile(r"[A-Za-z0-9_.-]+\.apk")
ICONS = {"webp": (b"RIFF", 8, b"WEBP"), "png": (b"\x89PNG\r\n\x1a\n", 0, b"")}
MAX_CATALOG = 8 * 1024 * 1024
MAX_IDSIG = 16 * 1024 * 1024
MAX_ICON = 1024 * 1024
CHUNK = 1024 * 1024
# Caps on what one catalog may list, far above GrapheneOS's catalog of 2026-11 (2,570 files, 2.53 GiB,
# the largest 132 MiB).
MAX_FILE = 512 * 1024 * 1024
MAX_TOTAL = 20 * 1024 * 1024 * 1024
MAX_FILES = 20000
# A run fails after its normal work when GrapheneOS's catalog is older than this, so that monitoring alerts.
MAX_AGE = 30 * 24 * 3600
# Files of a replaced catalog stay this long, for phones that read it just before.
KEEP_REPLACED = 24 * 3600


class Refused(Exception):
    pass


class Stale(Exception):
    """The run did its work, but GrapheneOS's catalog is older than MAX_AGE."""


def now():
    return int(time.time())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise Refused("redirects are refused")


OPENER = urllib.request.build_opener(NoRedirect)


def fetch(path, limit, out=None):
    """Bytes of UPSTREAM/path, or the byte count written to out. Larger than limit is refused."""
    url = UPSTREAM + "/" + path
    try:
        response = OPENER.open(urllib.request.Request(url, headers={"Accept-Encoding": "identity"}), timeout=60)
    except urllib.error.HTTPError as e:
        e.close()
        raise Refused(path + ": HTTP " + str(e.code))
    with response:
        if response.status != 200 or response.geturl() != url:
            raise Refused("unexpected response for " + path)
        # A dropped connection ends the body early without an error.
        length = response.headers.get("Content-Length")
        if out is None:
            data = response.read(limit + 1)
            if len(data) > limit:
                raise Refused(path + " exceeds " + str(limit) + " bytes")
            if length is not None and str(len(data)) != length:
                raise Refused(path + ": incomplete")
            return data
        total = 0
        while block := response.read(CHUNK):
            total += len(block)
            if total > limit:
                raise Refused(path + " exceeds " + str(limit) + " bytes")
            out.write(block)
        if length is not None and str(total) != length:
            raise Refused(path + ": incomplete")
        return total


def listed(name, package):
    """The App Store takes this package from GrapheneOS's catalog (Catalogs.kt, Catalog.GrapheneOS)."""
    names = [name] + ([package["originalPackage"]] if "originalPackage" in package else [])
    # In lower case, as Catalogs.kt compares them.
    return package.get("source") != "DiamaneOS" and not any(
        n in OURS or n in EXCLUDED or n == "de.diamaneos" or n.startswith("de.diamaneos.")
        for n in (n.lower() for n in names))


def verify_catalog(data, published):
    """GrapheneOS's catalog JSON, as the App Store reads it: JSON, a newline, the signature line, a newline."""
    if len(data) < 103 or data[-102:-101] != b"\n" or data[-1:] != b"\n":
        raise Refused("malformed catalog")
    work = published + ".check"
    os.makedirs(work, exist_ok=True)
    message, signature = os.path.join(work, "metadata.json"), os.path.join(work, "metadata.json.sig")
    with open(message, "wb") as f:
        f.write(data[:-102])
    with open(signature, "wb") as f:
        f.write(b"untrusted comment: signature from GrapheneOS app repository key 0\n" + data[-101:])
    if not os.path.isfile(SIGNIFY):
        raise Refused(SIGNIFY + " is not installed")
    result = subprocess.run([SIGNIFY, "-V", "-q", "-p", KEY, "-m", message, "-x", signature], capture_output=True)
    shutil.rmtree(work)
    if result.returncode != 0:
        raise Refused("catalog signature refused")
    try:
        catalog = json.loads(data[:-102], object_pairs_hook=unique_keys)
    except (ValueError, RecursionError) as e:
        raise Refused("unexpected catalog contents (" + str(e) + ")")
    if (not isinstance(catalog, dict) or type(catalog.get("time")) is not int
            or not isinstance(catalog.get("packages"), dict)):
        raise Refused("unexpected catalog contents")
    return catalog


def unique_keys(pairs):
    """A JSON object without a key twice, which parsers may read differently."""
    value = dict(pairs)
    if len(value) != len(pairs):
        raise Refused("a key is listed twice in the catalog")
    return value


def needed_files(catalog):
    """(path, kind, expected) for every file the App Store may fetch from this catalog, within the caps."""
    files = []
    for name, package in sorted(catalog["packages"].items()):
        if not isinstance(package, dict) or not isinstance(package.get("originalPackage", ""), str):
            raise Refused("unexpected package entry for " + repr(name))
        if not listed(name, package):
            continue
        if not NAME.fullmatch(name):
            raise Refused("unexpected package name " + repr(name))
        signatures = package.get("signatures", [])
        if not isinstance(signatures, list) or not all(isinstance(s, str) for s in signatures):
            raise Refused(name + ": unexpected signatures")
        if not isinstance(package.get("variants"), dict):
            raise Refused(name + ": unexpected variants")
        icon = package.get("iconType")
        # An unknown icon type only leaves the package without an icon.
        if isinstance(icon, str) and icon in ICONS:
            files.append(("packages/" + name + "/icon." + icon, "icon", (icon,) + sized(package, "iconSize", "iconSha256")))
        for code, variant in sorted(package["variants"].items()):
            if not VERSION.fullmatch(code):
                raise Refused(name + ": unexpected version " + repr(code))
            if not isinstance(variant, dict):
                raise Refused(name + "/" + code + ": unexpected variant")
            abis = variant.get("abis", [ABI])
            if not isinstance(abis, list) or not all(isinstance(a, str) for a in abis):
                raise Refused(name + "/" + code + ": unexpected abis")
            if ABI not in abis:
                continue
            columns = [variant.get(c, []) for c in ("apks", "apkHashes", "apkSizes", "apkGzSizes", "apkBrHashes", "apkBrSizes")]
            rows = list(zip(*columns)) if all(isinstance(c, list) for c in columns) else []
            if not rows or any(len(c) != len(rows) for c in columns):
                raise Refused(name + "/" + code + ": unexpected APK list")
            v4 = variant.get("hasV4Signatures", False)
            if not isinstance(v4, bool):
                raise Refused(name + "/" + code + ": unexpected hasV4Signatures")
            apk_deltas = deltas(name + "/" + code, variant, len(rows))
            for i, (apk, digest, size, gz_size, br_digest, br_size) in enumerate(rows):
                if (not all(isinstance(s, str) for s in (apk, digest, br_digest)) or not APK.fullmatch(apk)
                        or not all(map(SHA256.fullmatch, (digest, br_digest)))
                        or not all(type(n) is int and n > 0 for n in (size, gz_size, br_size))):
                    raise Refused(name + "/" + code + ": unexpected APK entry")
                path = "packages/" + name + "/" + code + "/" + apk
                files.append((path + ".gz", "apk", (digest, size, gz_size)))
                files.append((path + ".br", "br", (br_size, br_digest)))
                for source, delta_size, delta_digest in apk_deltas[i]:
                    files.append((path + "." + source + ".ina", "ina", (delta_size, delta_digest)))
                if v4:
                    files.append((path + ".idsig", "idsig", sized(variant, "v4SignatureSizes", "v4SignatureHashes", i)))
    check_caps(files)
    return files


def check_caps(files):
    """Refuses a path listed twice and files beyond the caps, each counted at the most it may fetch."""
    seen = set()
    for path, _, _ in files:
        if path in seen:
            raise Refused(path + " is listed twice")
        seen.add(path)
    if len(files) > MAX_FILES:
        raise Refused("the catalog lists " + str(len(files)) + " files, more than the cap of " + str(MAX_FILES))
    total = 0
    for path, kind, expected in files:
        size = fetch_limit(kind, expected)
        if size > MAX_FILE:
            raise Refused(path + " exceeds the cap of " + str(MAX_FILE) + " bytes")
        total += size
    if total > MAX_TOTAL:
        raise Refused("the catalog's files exceed the cap of " + str(MAX_TOTAL) + " bytes in total")


def deltas(where, variant, count):
    """For each of count APKs, (source version, size, SHA-256) of its deltas, read as Repo.kt reads them."""
    sources = variant.get("availableDeltaVersions", [])
    columns = [variant.get(c, []) for c in ("apkDeltaSizes", "apkDeltaHashes", "apkDeltaSrcHashes")]
    if (not all(isinstance(c, list) for c in [sources] + columns)
            or any(len(column) != len(sources) * count for column in columns)):
        raise Refused(where + ": unexpected delta list")
    found = [[] for _ in range(count)]
    for at, (size, digest, source_digest) in enumerate(zip(*columns)):
        source = sources[at % len(sources)]
        if type(source) is not int or not VERSION.fullmatch(str(source)) or type(size) is not int or size < 0:
            raise Refused(where + ": unexpected delta entry")
        # A size of 0 has no delta: the App Store takes the .br and ignores the hashes.
        if size == 0:
            continue
        if not all(isinstance(d, str) and SHA256.fullmatch(d) for d in (digest, source_digest)):
            raise Refused(where + ": unexpected delta entry")
        found[at // len(sources)].append((str(source), size, digest))
    return found


def sized(entry, size_key, hash_key, index=None):
    """(size, SHA-256) the catalog gives for a file, or () where it gives none."""
    if size_key not in entry and hash_key not in entry:
        return ()
    size, digest = entry.get(size_key), entry.get(hash_key)
    if index is not None:
        size = size[index] if isinstance(size, list) and index < len(size) else None
        digest = digest[index] if isinstance(digest, list) and index < len(digest) else None
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or not SHA256.fullmatch(str(digest)):
        raise Refused("unexpected " + size_key + " or " + hash_key)
    return size, digest


def check_exact(path, expected):
    """The file has the catalog's size and SHA-256, where the catalog gives them."""
    if not expected:
        return
    size, digest = expected
    if os.path.getsize(path) != size:
        raise Refused(path + ": size differs from the catalog")
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(CHUNK):
            h.update(block)
    if h.hexdigest() != digest:
        raise Refused(path + ": does not match the signed catalog")


def check_apk(path, expected):
    digest, size, gz_size = expected
    if os.path.getsize(path) != gz_size:
        raise Refused(path + ": compressed size differs from the catalog")
    h, total = hashlib.sha256(), 0
    try:
        with gzip.open(path, "rb") as f:
            while block := f.read(CHUNK):
                total += len(block)
                if total > size:
                    break
                h.update(block)
    except (OSError, EOFError, zlib.error):
        total = -1
    if total != size or h.hexdigest() != digest:
        raise Refused(path + ": does not match the signed catalog")


def check_idsig(path):
    """APK Signature Scheme v4 file: version 2, then length-prefixed hashing info, signing info and an optional tree."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 12 or struct.unpack("<i", data[:4])[0] != 2:
        raise Refused(path + ": not a v4 signature")
    at, parts = 4, 0
    while at < len(data):
        if at + 4 > len(data):
            raise Refused(path + ": truncated v4 signature")
        length = struct.unpack("<i", data[at:at + 4])[0]
        if length < 0 or at + 4 + length > len(data):
            raise Refused(path + ": truncated v4 signature")
        at += 4 + length
        parts += 1
    if parts not in (2, 3):
        raise Refused(path + ": unexpected v4 signature layout")


def check_icon(path, kind):
    magic, at, tag = ICONS[kind]
    with open(path, "rb") as f:
        head = f.read(16)
    if not head.startswith(magic) or head[at:at + len(tag)] != tag:
        raise Refused(path + ": not a " + kind + " image")


def check(path, kind, expected):
    if kind == "apk":
        check_apk(path, expected)
    elif kind in ("br", "ina"):
        check_exact(path, expected)
    elif kind == "idsig":
        check_exact(path, expected)
        check_idsig(path)
    else:
        check_exact(path, expected[1:])
        check_icon(path, expected[0])


def mirror_file(root, path, kind, expected, verified, new_catalog, staged):
    """Fetches and checks one file unless it is already in place. Returns the bytes fetched."""
    target = os.path.join(root, path)
    key = [kind, list(expected)]
    if kind == "icon":
        if os.path.isfile(target) and not new_catalog:
            return 0
        try:
            # The published catalog may list the icon at this path, so it is replaced after the catalog.
            loaded = fetch_file(target + ".new", path, kind, expected, verified, key)
            staged.append(target)
            return loaded
        except (Refused, OSError, http.client.HTTPException) as e:
            print("icon kept as it was: " + path + " (" + str(e) + ")")
            return 0
    if os.path.isfile(target):
        # Versions are immutable: a published file is kept, and it must still match the catalog.
        stat = os.stat(target)
        if verified.get(path) != key + [stat.st_size, stat.st_mtime_ns]:
            check(target, kind, expected)
            verified[path] = key + [stat.st_size, stat.st_mtime_ns]
        return 0
    return fetch_file(target, path, kind, expected, verified, key)


def fetch_limit(kind, expected):
    """The most bytes fetched for a file: its size in the catalog, or the limit where it gives none."""
    return {"apk": lambda: expected[2], "br": lambda: expected[0], "ina": lambda: expected[0],
            "idsig": lambda: min(expected[0], MAX_IDSIG) if expected else MAX_IDSIG,
            "icon": lambda: min(expected[1], MAX_ICON) if len(expected) > 1 else MAX_ICON}[kind]()


def fetch_file(target, path, kind, expected, verified, key):
    os.makedirs(os.path.dirname(target), exist_ok=True)
    tmp = target + ".tmp"
    try:
        with open(tmp, "wb") as out:
            loaded = fetch(path, fetch_limit(kind, expected), out)
            out.flush()
            os.fsync(out.fileno())
        check(tmp, kind, expected)
    except BaseException:
        os.remove(tmp)
        raise
    os.replace(tmp, target)
    stat = os.stat(target)
    verified[path] = key + [stat.st_size, stat.st_mtime_ns]
    return loaded


def changes(previous, catalog):
    """Packages added, dropped or signed by others since the previous catalog, for the log."""
    old = {n: p for n, p in previous["packages"].items() if listed(n, p)} if previous else {}
    new = {n: p for n, p in catalog["packages"].items() if listed(n, p)}
    if not old:
        return []
    notes = ["added " + n for n in sorted(set(new) - set(old))]
    notes += ["dropped " + n for n in sorted(set(old) - set(new))]
    notes += ["other signers for " + n + ": " + ", ".join(new[n].get("signatures", []))
              for n in sorted(set(new) & set(old))
              if sorted(new[n].get("signatures", [])) != sorted(old[n].get("signatures", []))]
    return notes


def write_json(path, value):
    with open(path + ".tmp", "w") as f:
        json.dump(value, f, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(path + ".tmp", path)


def prune(root, keep):
    removed = 0
    packages = os.path.join(root, "packages")
    for directory, dirs, files in os.walk(packages, topdown=False):
        for name in files:
            path = os.path.relpath(os.path.join(directory, name), root)
            if path not in keep:
                os.remove(os.path.join(root, path))
                removed += 1
        if directory != packages and not os.listdir(directory):
            os.rmdir(directory)
    return removed


def mirror(root, state):
    os.makedirs(state, exist_ok=True)
    with open(os.path.join(state, "lock"), "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("another mirror run holds the lock")
        locked_mirror(root, state)


def locked_mirror(root, state):
    published = os.path.join(root, CATALOG)
    # The newest catalog time ever published, and until when each file of a replaced catalog stays.
    remembered_path = os.path.join(state, "catalogs.json")
    remembered = {"floor": 0, "kept": {}}
    if os.path.isfile(remembered_path):
        with open(remembered_path) as f:
            remembered = json.load(f)
    data = fetch(CATALOG, MAX_CATALOG)
    catalog = verify_catalog(data, os.path.join(state, "upstream"))
    previous = None
    if os.path.isfile(published):
        with open(published, "rb") as f:
            old = f.read()
        previous = verify_catalog(old, os.path.join(state, "upstream"))
        # A host without a floor yet takes the published catalog's time.
        if previous["time"] > remembered["floor"]:
            remembered["floor"] = previous["time"]
            write_json(remembered_path, remembered)
        if catalog["time"] < previous["time"]:
            raise Refused("GrapheneOS's catalog is older than the published one")
    if catalog["time"] < remembered["floor"]:
        raise Refused("GrapheneOS's catalog is older than one published before (" + str(remembered["floor"]) + ")")
    files = needed_files(catalog)
    new_catalog = previous is None or data != old
    current = {path for path, _, _ in files}
    replaced = [] if not new_catalog or previous is None else [
        path for path, _, _ in needed_files(previous) if path not in current]
    verified_path = os.path.join(state, "verified.json")
    verified = {}
    if os.path.isfile(verified_path):
        with open(verified_path) as f:
            verified = json.load(f)
    loaded = 0
    staged = []
    try:
        for path, kind, expected in files:
            loaded += mirror_file(root, path, kind, expected, verified, new_catalog, staged)
    finally:
        write_json(verified_path, verified)
    if new_catalog:
        until = now() + KEEP_REPLACED
        for path in replaced:
            remembered["kept"][path] = max(until, remembered["kept"].get(path, 0))
        remembered["floor"] = max(remembered["floor"], catalog["time"])
        write_json(remembered_path, remembered)
        with open(published + ".tmp", "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(published + ".tmp", published)
    for target in staged:
        os.replace(target + ".new", target)
    moment = now()
    remembered["kept"] = {path: until for path, until in remembered["kept"].items() if until > moment}
    keep = current | set(remembered["kept"]) | {CATALOG}
    removed = prune(root, keep)
    for path in list(verified):
        if path not in keep:
            del verified[path]
    write_json(verified_path, verified)
    write_json(remembered_path, remembered)
    print("published GrapheneOS catalog " + str(catalog["time"]) + ": " + str(len(files)) + " files, "
          + str(loaded // 1000000) + " MB fetched, " + str(removed) + " removed, "
          + str(len(set(remembered["kept"]) - current)) + " kept from replaced catalogs")
    for note in changes(previous, catalog):
        print("GrapheneOS's catalog: " + note)
    age = moment - catalog["time"]
    if age > MAX_AGE:
        raise Stale("GrapheneOS's catalog " + str(catalog["time"]) + " is " + str(age // 86400)
                    + " days old, more than " + str(MAX_AGE // 86400))


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1].startswith("-"):
        sys.exit(__doc__)
    try:
        mirror(os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2]))
    except Refused as e:
        print("refused: " + str(e), file=sys.stderr)
        sys.exit(2)
    except Stale as e:
        print("alert: " + str(e) + ". It is still served.", file=sys.stderr)
        sys.exit(3)
