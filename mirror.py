#!/usr/bin/env python3
"""Mirror GrapheneOS's signed app repository into a catalog work tree.

./mirror.py WORK          copy the inventory and scripts into WORK and mirror every listed package
./mirror.py --check WORK  after generate.py: mirrored packages match GrapheneOS's catalog exactly

The inventory is apps/packages/*/common-props.toml. Packages with source DiamaneOS are our own
builds and never mirrored. Every other listed package is mirrored for arm64-v8a from GrapheneOS's
catalog, checked against its signature (grapheneos-apps.0.pub) and its SHA-256 and sizes. A package
that is not in the inventory, or whose signers or properties differ from it, is held for review in
WORK/held.json. Versions GrapheneOS no longer lists stay as channel "old", as GrapheneOS keeps them.
Packages in EXCLUDED are never listed, whatever GrapheneOS's catalog says about them.
"""

import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tomllib
import urllib.request

UPSTREAM = "https://apps.grapheneos.org"
CATALOG = "metadata.1.0.sjson"
KEY = "grapheneos-apps.0.pub"
ABI = "arm64-v8a"
REPO = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = ["generate.py", "compress-apks", "process-static", "import-apks.py"]
# generate.py derives these from the APKs. Everything else of a version comes from its toml files.
DERIVED = {"versionCode", "apks", "apkHashes", "apkSizes", "apkGzSizes", "apkBrSizes", "versionName",
           "label", "minSdk", "abis", "hasV4Signatures", "channel"}
# Package properties the inventory sets for itself.
OWN_PROPS = {"variants", "signatures", "source", "description", "iconType", "hasFsVeritySignatures"}
# GrapheneOS's own apps that do not belong in our catalog. Info shows GrapheneOS's release news.
EXCLUDED = {"app.grapheneos.info"}


def fetch(path, limit):
    with urllib.request.urlopen(UPSTREAM + "/" + path, timeout=60) as response:
        if response.status != 200 or response.geturl() != UPSTREAM + "/" + path:
            raise Exception("unexpected response for " + path)
        data = response.read(limit + 1)
    if len(data) > limit:
        raise Exception(path + " exceeds " + str(limit) + " bytes")
    return data


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(v) for v in value) + "]"
    raise Exception("unsupported property value: " + repr(value))


def write_toml(path, props):
    text = "".join(k + " = " + toml_value(v) + "\n" for k, v in sorted(props.items()))
    assert tomllib.loads(text) == props
    with open(path + ".tmp", "w") as f:
        f.write(text)
    os.replace(path + ".tmp", path)


def load_inventory():
    packages_dir = os.path.join(REPO, "apps/packages")
    inventory = {}
    for name in sorted(os.listdir(packages_dir)):
        with open(os.path.join(packages_dir, name, "common-props.toml"), "rb") as f:
            inventory[name] = tomllib.load(f)
    if EXCLUDED & set(inventory):
        raise Exception("excluded packages in the inventory: " + ", ".join(sorted(EXCLUDED & set(inventory))))
    return inventory


def prepare(work, inventory):
    """Copy the scripts, static files and inventory. Version directories stay in place."""
    for name in SCRIPTS:
        shutil.copy2(os.path.join(REPO, name), os.path.join(work, name))
    shutil.copytree(os.path.join(REPO, "static"), os.path.join(work, "static"), dirs_exist_ok=True)
    packages = os.path.join(work, "apps/packages")
    os.makedirs(packages, exist_ok=True)
    for name in os.listdir(packages):
        if name not in inventory:
            shutil.rmtree(os.path.join(packages, name))
    for name in inventory:
        os.makedirs(os.path.join(packages, name), exist_ok=True)
        for f in ("common-props.toml", "icon.webp"):
            source = os.path.join(REPO, "apps/packages", name, f)
            target = os.path.join(packages, name, f)
            if os.path.isfile(source):
                shutil.copy2(source, target)
            elif os.path.exists(target):
                os.remove(target)


def verified_catalog(work):
    """GrapheneOS's catalog JSON after its signify signature and timestamp checks."""
    data = fetch(CATALOG, 16 * 1024 * 1024)
    # As the App Store reads it: JSON, a newline, the signature line and a newline.
    if len(data) < 103 or data[-102:-101] != b"\n" or data[-1:] != b"\n":
        raise Exception("malformed upstream catalog")
    upstream = os.path.join(work, "upstream")
    os.makedirs(upstream, exist_ok=True)
    message, signature = os.path.join(upstream, "metadata.1.json.new"), os.path.join(upstream, "metadata.1.json.sig")
    with open(message, "wb") as f:
        f.write(data[:-102])
    with open(signature, "wb") as f:
        f.write(b"untrusted comment: signature from GrapheneOS app repository key 0\n" + data[-101:])
    subprocess.run(["signify", "-V", "-q", "-p", os.path.join(REPO, KEY), "-m", message, "-x", signature], check=True)
    with open(message, "rb") as f:
        catalog = json.loads(f.read())
    state = os.path.join(upstream, "state.json")
    if os.path.isfile(state):
        with open(state) as f:
            if catalog["time"] < json.load(f)["time"]:
                raise Exception("upstream catalog is older than the last mirrored one")
    os.replace(message, os.path.join(upstream, "metadata.1.json"))
    with open(state, "w") as f:
        json.dump({"time": catalog["time"]}, f)
    return catalog


def hold_reason(name, package, inventory):
    listed = inventory.get(name)
    if listed is None:
        return "new package"
    if sorted(package["signatures"]) != sorted(listed["signatures"]):
        return "signers differ: " + ", ".join(sorted(package["signatures"]))
    theirs = {k: v for k, v in package.items() if k not in OWN_PROPS}
    ours = {k: v for k, v in listed.items() if k not in OWN_PROPS}
    if theirs != ours:
        return "properties differ: " + ", ".join(sorted(k for k in set(theirs) | set(ours) if theirs.get(k) != ours.get(k)))
    return None


def mirrored_variants(package):
    return {code: v for code, v in package["variants"].items() if "abis" not in v or ABI in v["abis"]}


def mirror_apk(directory, url, name, digest, size, gz_size, br_size, v4):
    apk = os.path.join(directory, name)
    files = [apk, apk + ".gz", apk + ".br"] + ([apk + ".idsig"] if v4 else [])
    if all(os.path.isfile(f) for f in files) and os.path.getsize(apk) == size and sha256(apk) == digest:
        return 0
    loaded = 0
    for suffix, expected in ((".gz", gz_size), (".br", br_size)):
        data = fetch(url + suffix, expected)
        if len(data) != expected:
            raise Exception(url + suffix + " has the wrong size")
        with open(apk + suffix + ".tmp", "wb") as f:
            f.write(data)
        loaded += len(data)
    with gzip.open(apk + ".gz.tmp") as source, open(apk + ".tmp", "wb") as target:
        shutil.copyfileobj(source, target)
    unpacked = subprocess.run(["brotli", "-d", "-c", apk + ".br.tmp"], check=True, capture_output=True).stdout
    if os.path.getsize(apk + ".tmp") != size or sha256(apk + ".tmp") != digest \
            or hashlib.sha256(unpacked).hexdigest() != digest:
        raise Exception(url + " does not match the signed catalog")
    if v4:
        data = fetch(url + ".idsig", 16 * 1024 * 1024)
        with open(apk + ".idsig.tmp", "wb") as f:
            f.write(data)
        loaded += len(data)
        subprocess.run(["apksigner", "verify", "--v4-signature-file", apk + ".idsig.tmp", apk + ".tmp"],
                       check=True, capture_output=True)
    # generate.py requires the same modification time on an APK and its compressed copies.
    stat = os.stat(apk + ".tmp")
    for suffix in (".gz", ".br") + ((".idsig",) if v4 else ()):
        os.utime(apk + suffix + ".tmp", ns=(stat.st_atime_ns, stat.st_mtime_ns))
        os.replace(apk + suffix + ".tmp", apk + suffix)
    if os.path.exists(apk + ".sha256"):
        os.remove(apk + ".sha256")
    os.replace(apk + ".tmp", apk)
    return loaded


def mirror_package(work, name, package):
    directory = os.path.join(work, "apps/packages", name)
    variants = mirrored_variants(package)
    loaded = 0
    for code, variant in variants.items():
        version = os.path.join(directory, code)
        os.makedirs(version, exist_ok=True)
        rows = zip(variant["apks"], variant["apkHashes"], variant["apkSizes"], variant["apkGzSizes"], variant["apkBrSizes"])
        for apk, digest, size, gz_size, br_size in rows:
            url = "packages/" + name + "/" + code + "/" + apk
            loaded += mirror_apk(version, url, apk, digest, size, gz_size, br_size, variant.get("hasV4Signatures", False))
        write_toml(os.path.join(version, "channel.toml"), {"channel": variant["channel"]})
        props = {k: v for k, v in variant.items() if k not in DERIVED}
        if props:
            write_toml(os.path.join(version, "props.toml"), props)
        elif os.path.exists(os.path.join(version, "props.toml")):
            os.remove(os.path.join(version, "props.toml"))
    for code in os.listdir(directory):
        if os.path.isdir(os.path.join(directory, code)) and code not in variants:
            write_toml(os.path.join(directory, code, "channel.toml"), {"channel": "old"})
    return len(variants), loaded


def mirror(work):
    inventory = load_inventory()
    os.makedirs(work, exist_ok=True)
    prepare(work, inventory)
    catalog = verified_catalog(work)
    held, total, loaded = [], 0, 0
    for name, package in sorted(catalog["packages"].items()):
        if name in EXCLUDED or inventory.get(name, {}).get("source") == "DiamaneOS":
            continue
        reason = hold_reason(name, package, inventory)
        if reason:
            held.append({"package": name, "reason": reason})
            continue
        count, size = mirror_package(work, name, package)
        total += count
        loaded += size
        print("mirrored " + name + ": " + str(count) + " versions")
    with open(os.path.join(work, "held.json"), "w") as f:
        json.dump(held, f, indent=1)
    for entry in held:
        print("held for review: " + entry["package"] + " (" + entry["reason"] + ")")
    print(str(total) + " versions mirrored, " + str(loaded // 1000000) + " MB downloaded, " + str(len(held)) + " held")


def check(work):
    with open(os.path.join(work, "upstream/metadata.1.json")) as f:
        upstream = json.load(f)["packages"]
    with open(os.path.join(work, "apps/metadata.1.json")) as f:
        ours = json.load(f)["packages"]
    with open(os.path.join(work, "held.json")) as f:
        held = {entry["package"] for entry in json.load(f)}
    problems = []
    for name, package in ours.items():
        if name in EXCLUDED:
            problems.append(name + " is excluded but listed")
            continue
        if package["source"] == "DiamaneOS":
            continue
        theirs = upstream.get(name)
        if theirs is None or name in held:
            problems.append(name + " is listed but not mirrored")
            continue
        if {k: v for k, v in package.items() if k not in OWN_PROPS} != {k: v for k, v in theirs.items() if k not in OWN_PROPS} \
                or sorted(package["signatures"]) != sorted(theirs["signatures"]):
            problems.append(name + ": package properties differ")
        if package["variants"] != mirrored_variants(theirs):
            problems.append(name + ": versions differ")
    for problem in problems:
        print(problem)
    if problems:
        sys.exit(1)
    print("mirrored packages match GrapheneOS's catalog")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        check(os.path.abspath(sys.argv[2]))
    elif len(sys.argv) == 2 and not sys.argv[1].startswith("-"):
        mirror(os.path.abspath(sys.argv[1]))
    else:
        sys.exit(__doc__)
