#!/usr/bin/env python3
"""Prepare and check the work tree of our catalog. It lists only apps signed with our keys.

./prepare.py WORK                  copy the inventory, scripts and static files into WORK
./prepare.py --check WORK KEY.pub  after generate.py: the signed catalog verifies with apps.0's public
                                   key and lists only the inventory, with its signers, single APKs, a
                                   label in each version and an icon for each app on the main screen

The inventory is apps/packages/*/common-props.toml. GrapheneOS's apps are not in our catalog: the App
Store reads GrapheneOS's own catalog for them, mirrored by grapheneos-mirror.py, and refuses our
packages from it. From our catalog it refuses any package not signed with our keys, or that
GrapheneOS's catalog lists (Catalogs.kt).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib

REPO = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = ["generate.py", "compress-apks", "process-static", "import-apks.py"]
# Debian's OpenBSD signify. Debian's plain signify is an unrelated mail tool.
SIGNIFY = "/usr/bin/signify-openbsd"
# The App Store refuses an older catalog of ours on a phone without one (Catalog.DiamaneOS.minTimestamp
# in Catalogs.kt). Raised with it at each rebase.
MIN_TIME = 1_792_500_000
CATALOG = "apps/metadata.1.0.sjson"
# Our app signing certificates (DIAMANEOS_SIGNERS in Catalogs.kt): App Store, Camera, Auditor.
SIGNERS = {
    "559ffb104edd9386a39d512063cb7458c5ec0e29c9b52a91068ce950dd768a47",
    "285a091a913f1485ce16f280f06b2609dc1af6cca786e45b6f5356aa7e86fa61",
    "427bfd360586b829475f37abffd2548d93db3618e45c994de416469ef04bc2ec",
}
# GrapheneOS's apps the App Store never lists (EXCLUDED_PACKAGES in Catalogs.kt).
EXCLUDED = {"app.grapheneos.info", "app.attestation.auditor"}
# The App Store reads at most 1 MiB of an icon (DownloadIconLoader.kt).
MAX_ICON = 1024 * 1024


def load_inventory():
    packages_dir = os.path.join(REPO, "apps/packages")
    inventory = {}
    for name in sorted(os.listdir(packages_dir)):
        with open(os.path.join(packages_dir, name, "common-props.toml"), "rb") as f:
            inventory[name] = tomllib.load(f)
    problems = sorted(name for name in inventory if name.lower() in EXCLUDED)
    problems += [name + " is not source DiamaneOS" for name, p in inventory.items() if p.get("source") != "DiamaneOS"]
    problems += [name + " needs one of our signers" for name, p in inventory.items()
                 if len(p.get("signatures", [])) != 1 or p["signatures"][0] not in SIGNERS]
    problems += [name + " uses the original-package system" for name, p in inventory.items() if "originalPackage" in p]
    if problems:
        raise Exception("not our catalog's packages: " + ", ".join(problems))
    return inventory


def prepare(work):
    """Copy the scripts, static files and inventory. Version directories stay in place."""
    inventory = load_inventory()
    os.makedirs(work, exist_ok=True)
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
    print("prepared " + str(len(inventory)) + " packages: " + ", ".join(sorted(inventory)))


def signed_catalog(work, key):
    """The JSON of the catalog the App Store reads, after its signature check with key."""
    with open(os.path.join(work, CATALOG), "rb") as f:
        data = f.read()
    if len(data) < 103 or data[-102:-101] != b"\n" or data[-1:] != b"\n":
        sys.exit("malformed signed catalog")
    with tempfile.TemporaryDirectory() as tmp:
        message, signature = os.path.join(tmp, "metadata.json"), os.path.join(tmp, "metadata.json.sig")
        with open(message, "wb") as f:
            f.write(data[:-102])
        with open(signature, "wb") as f:
            f.write(b"untrusted comment: signature from the DiamaneOS app catalog key\n" + data[-101:])
        if subprocess.run([SIGNIFY, "-V", "-q", "-p", key, "-m", message, "-x", signature]).returncode != 0:
            sys.exit("the signed catalog does not verify with " + key)
    return json.loads(data[:-102])


def icon_problem(work, name, package):
    """Each app on the App Store's main screen needs its WebP icon in the tree that is published."""
    icon = package.get("iconType")
    if icon is None:
        return name + ": no icon" if package.get("isTopLevel", True) is not False else None
    path = os.path.join(work, "apps/packages", name, "icon." + str(icon))
    if icon != "webp" or not os.path.isfile(path):
        return name + ": icon missing"
    with open(path, "rb") as f:
        data = f.read(MAX_ICON + 1)
    if len(data) > MAX_ICON or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return name + ": icon is not a WebP image of at most 1 MiB"
    return None


def check(work, key):
    inventory = load_inventory()
    catalog = signed_catalog(work, key)
    packages = catalog["packages"]
    problems = []
    # Catches a signing machine with a wrong clock.
    if not isinstance(catalog.get("time"), int) or catalog["time"] < MIN_TIME:
        problems.append("the catalog's time is before the App Store's floor " + str(MIN_TIME))
    for name, package in sorted(packages.items()):
        listed = inventory.get(name)
        if listed is None:
            problems.append(name + " is not ours")
        elif package.get("source") != "DiamaneOS" or "originalPackage" in package:
            problems.append(name + ": not as the App Store takes our packages")
        elif sorted(package["signatures"]) != sorted(listed["signatures"]):
            problems.append(name + ": signers differ from the inventory")
        # The App Store parses each APK from our catalog for its signer, and a split does not parse.
        elif any(v.get("apks") != ["base.apk"] for v in package.get("variants", {}).values()):
            problems.append(name + ": not a single APK")
        # The App Store reads each version's label and refuses the whole catalog without one (RPackage in Repo.kt).
        if any(not isinstance(v, dict) or not isinstance(v.get("label"), str) or not v["label"].strip()
               for v in package.get("variants", {}).values()):
            problems.append(name + ": a version without a label")
        if listed is not None and (problem := icon_problem(work, name, package)):
            problems.append(problem)
    for problem in problems:
        print(problem)
    if problems:
        sys.exit(1)
    print("our catalog lists only our signed packages: " + ", ".join(sorted(packages)))


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--check":
        check(os.path.abspath(sys.argv[2]), os.path.abspath(sys.argv[3]))
    elif len(sys.argv) == 2 and not sys.argv[1].startswith("-"):
        prepare(os.path.abspath(sys.argv[1]))
    else:
        sys.exit(__doc__)
