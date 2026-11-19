#!/usr/bin/env python3
"""Prepare and check the work tree of the DiamaneOS catalog. It lists only apps signed with the project's keys.

./prepare.py WORK                  copy the inventory, scripts and static files into WORK
./prepare.py --check WORK KEY.pub PUBLISHED [--allow-drop PACKAGE[:CHANNEL]]...
                                   after generate.py: the signed catalog verifies with apps.0's public
                                   key and lists only the inventory, with its signers, single APKs, a
                                   label in each version and an icon for each app on the main screen.
                                   It is newer than PUBLISHED, the signed catalog as served, keeps its
                                   packages and offers each channel no lower version than it, unless
                                   --allow-drop names the package or PACKAGE:CHANNEL
./prepare.py --check --first WORK KEY.pub
                                   the same for a first release, which has no published catalog

The inventory is apps/packages/*/common-props.toml. GrapheneOS's apps are not in this catalog: the App Store
reads GrapheneOS's own catalog for them, mirrored by grapheneos-mirror.py, and refuses the project's packages
from it. From this catalog it refuses any package not signed with the project's keys, or that
GrapheneOS's catalog lists (Catalogs.kt).
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

REPO = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = ["generate.py", "compress-apks", "process-static", "import-apks.py"]
# Debian's OpenBSD signify. Debian's plain signify is an unrelated mail tool.
SIGNIFY = "/usr/bin/signify-openbsd"
# The App Store refuses an older catalog on a phone without one (Catalog.DiamaneOS.minTimestamp
# in Catalogs.kt). Raised with it at each rebase.
MIN_TIME = 1_792_550_000
CATALOG = "apps/metadata.1.0.sjson"
# The DiamaneOS app signing certificates (DIAMANEOS_SIGNERS in Catalogs.kt): App Store, Camera, Auditor.
SIGNERS = {
    "559ffb104edd9386a39d512063cb7458c5ec0e29c9b52a91068ce950dd768a47",
    "285a091a913f1485ce16f280f06b2609dc1af6cca786e45b6f5356aa7e86fa61",
    "427bfd360586b829475f37abffd2548d93db3618e45c994de416469ef04bc2ec",
}
# Other makers' apps the catalog offers (PINNED_PACKAGES in Catalogs.kt): each name with its signer lineage, the
# SHA-256 of each certificate the maker's key has had, oldest first, and the system features every version of
# it must list (the App Store offers a version only on an OS build that declares them). The inventory lists
# the one certificate that signs the APK, as apksigner verify prints it, and it must be one of the lineage.
# com.fps.camera: Fairphone's own camera app, signed by TCL, whose key was rotated once. Its APK is signed with
# the second certificate. It needs the camera algorithm service. An OS build for a device that ships this app
# declares it with de.diamaneos.fairphone_camera.
# The last value is the prefix of one further feature each version must list. It names the version's APK: the
# prefix and the first 16 hex characters of the APK's SHA-256. The app loads stock libraries of the OS build,
# so an OS build declares that feature only for the APK of the stock release it was built from, and a phone is
# offered that APK and no other. APK 3b271af8fac2df22... is de.diamaneos.fairphone_camera.apk_3b271af8fac2df22.
PINNED = {
    "com.fps.camera": (["0f00b338d27aa1cd1c4a00e8584501ffb36775a07af42e1cc394ca1ed0908470",
                        "228b9b34992235ff4efa72f771f79a48ca8db679920fcfd8ae8fe3e25a7a4852"],
                       ["de.diamaneos.fairphone_camera"], "de.diamaneos.fairphone_camera.apk_"),
}
# Packages the App Store updates together. Each lists its group (one release channel for all of it) and the
# dependencies it names without a version, so an update of it also takes a newer dependency in the same install.
# Camera names CameraProcessor. CameraProcessor names nothing: with Camera as its dependency, a user who disables
# Camera would see a missing dependency at each CameraProcessor update. When both are outdated, the App Store's
# update of all apps installs them together anyway, through Camera's dependency.
LINKED = {
    "app.grapheneos.camera": ("camera", ["de.diamaneos.camera.processor"]),
    "de.diamaneos.camera.processor": ("camera", None),
}
# GrapheneOS's apps the App Store never lists (EXCLUDED_PACKAGES in Catalogs.kt).
EXCLUDED = {"app.grapheneos.info", "app.attestation.auditor"}
# The App Store reads at most 1 MiB of an icon (DownloadIconLoader.kt).
MAX_ICON = 1024 * 1024
# Release channels from least to most stable (ReleaseChannel in Repo.kt). A version without one is stable.
CHANNELS = ["alpha", "beta", "stable"]
# A version code as generate.py names it and the App Store reads it as a number (Repo.kt).
VERSION = re.compile(r"[1-9][0-9]{0,18}")


def load_inventory():
    packages_dir = os.path.join(REPO, "apps/packages")
    inventory = {}
    for name in sorted(os.listdir(packages_dir)):
        with open(os.path.join(packages_dir, name, "common-props.toml"), "rb") as f:
            inventory[name] = tomllib.load(f)
    problems = sorted(name for name in inventory if name.lower() in EXCLUDED)
    problems += [name + " is not source DiamaneOS" for name, p in inventory.items() if p.get("source") != "DiamaneOS"]
    problems += [name + " needs one of the DiamaneOS signers" for name, p in inventory.items()
                 if name not in PINNED and (len(p.get("signatures", [])) != 1 or p["signatures"][0] not in SIGNERS)]
    problems += [name + " needs one signer of its pinned lineage" for name, p in inventory.items()
                 if name in PINNED and (len(p.get("signatures", [])) != 1 or p["signatures"][0] not in PINNED[name][0])]
    # A label here replaces the APK's own label in every version (replace_label in generate.py). Only a pinned
    # maker's app may have one. DiamaneOS apps show the name their APK carries.
    problems += [name + " may not replace its APK's label" for name, p in inventory.items()
                 if "label" in p and name not in PINNED]
    problems += [name + " needs a label that is a non-empty string" for name, p in inventory.items()
                 if "label" in p and name in PINNED and (not isinstance(p["label"], str) or not p["label"].strip())]
    problems += [name + " uses the original-package system" for name, p in inventory.items() if "originalPackage" in p]
    if problems:
        raise Exception("not packages of the DiamaneOS catalog: " + ", ".join(problems))
    return inventory


def pinned_version_problem(work, name, version, variant):
    """A pinned app's version lists the app's features and the one feature that names its APK in the tree,
    and nothing else. The APK's SHA-256 is computed here."""
    _, features, prefix = PINNED[name]
    apk = os.path.join(work, "apps/packages", name, version, "base.apk")
    if not os.path.isfile(apk):
        return name + " " + version + ": no APK in the tree"
    digest = hashlib.sha256()
    with open(apk, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    wanted = features + [prefix + digest.hexdigest()[:16]]
    listed = variant.get("features") if isinstance(variant, dict) else None
    if not isinstance(listed, list) or not all(isinstance(f, str) for f in listed) or sorted(listed) != sorted(wanted):
        return name + " " + version + ": not limited to " + ", ".join(wanted)
    if "apkHashes" in variant and variant["apkHashes"] != [digest.hexdigest()]:
        return name + " " + version + ": the catalog lists another APK than the tree holds"
    return None


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


def signed_catalog(path, key):
    """The JSON of the catalog the App Store reads, after its signature check with key."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 103 or data[-102:-101] != b"\n" or data[-1:] != b"\n":
        sys.exit("malformed signed catalog " + path)
    with tempfile.TemporaryDirectory() as tmp:
        message, signature = os.path.join(tmp, "metadata.json"), os.path.join(tmp, "metadata.json.sig")
        with open(message, "wb") as f:
            f.write(data[:-102])
        with open(signature, "wb") as f:
            f.write(b"untrusted comment: signature from the DiamaneOS app catalog key\n" + data[-101:])
        if subprocess.run([SIGNIFY, "-V", "-q", "-p", key, "-m", message, "-x", signature]).returncode != 0:
            sys.exit(path + " does not verify with " + key)
    try:
        return json.loads(data[:-102])
    except (ValueError, RecursionError):
        sys.exit(path + " is not JSON")


def unreadable(catalog):
    """Why the App Store could not read the catalog as the checks below read it, or None. It refuses the whole
    catalog when a package has no signers or versions object, or a version no number or a channel it does not
    know (Repo.kt)."""
    if not isinstance(catalog, dict) or type(catalog.get("time")) is not int \
            or not isinstance(catalog.get("packages"), dict):
        return "not a catalog with a time and packages"
    for name, package in catalog["packages"].items():
        if not isinstance(package, dict) or not isinstance(package.get("variants"), dict):
            return name + ": no versions object"
        if not isinstance(package.get("signatures"), list) or not all(isinstance(s, str) for s in package["signatures"]):
            return name + ": no list of signers"
        for code, variant in package["variants"].items():
            if not VERSION.fullmatch(code) or not isinstance(variant, dict) \
                    or variant.get("channel", "stable") not in CHANNELS:
                return name + " " + code + ": not a version the App Store reads"
    return None


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


def offered(package):
    """The version code a phone on each channel is offered, as the App Store picks it: the highest version of each
    channel, then for channel C the least stable of them at C or more stable, else the most stable one (findRPackage
    in Repo.kt). Empty when the package has no version. minSdk, ABIs, features and static dependencies are left out."""
    best = {}
    for code, variant in package.get("variants", {}).items():
        channel = variant.get("channel", "stable") if isinstance(variant, dict) else None
        if channel in CHANNELS:
            best[channel] = max(best.get(channel, 0), int(code))
    result = {}
    for i, channel in enumerate(CHANNELS):
        stabler = [best[c] for c in CHANNELS[i:] if c in best]
        if stabler:
            result[channel] = stabler[0]
        elif best:
            result[channel] = best[max(best, key=CHANNELS.index)]
    return result


def published_problems(catalog, published, allowed):
    """The catalog is newer than the one last published, keeps each of its packages and offers a phone on each
    channel no lower version code. Only --allow-drop PACKAGE or PACKAGE:CHANNEL lets one go, and each one must be used."""
    problems, used = [], set()
    if not isinstance(published.get("time"), int) or not isinstance(catalog.get("time"), int) \
            or catalog["time"] <= published["time"]:
        problems.append("the catalog's time is not after the published catalog's " + str(published.get("time")))

    def drop(name, problem):
        if name in allowed:
            used.add(name)
        else:
            problems.append(name + ": " + problem)

    for name, package in sorted(published["packages"].items()):
        before, now = offered(package), offered(catalog["packages"].get(name, {}))
        if before and not now:
            drop(name, "in the published catalog, missing from this one")
            continue
        for channel in before:
            if now[channel] < before[channel]:
                drop(name + ":" + channel, "a phone on " + channel + " gets " + str(now[channel])
                     + ", below the published " + str(before[channel]))
    problems += ["--allow-drop " + name + ": the catalog keeps it" for name in sorted(set(allowed) - used)]
    return problems


def check(work, key, published, allowed=()):
    """published is the signed catalog apps.diamaneos.de serves, None only for a first release (--first)."""
    inventory = load_inventory()
    catalog = signed_catalog(os.path.join(work, CATALOG), key)
    last = None if published is None else signed_catalog(published, key)
    for path, value in ((os.path.join(work, CATALOG), catalog), (published, last)):
        if path is not None and (problem := unreadable(value)) is not None:
            sys.exit(path + ": " + problem)
    packages = catalog["packages"]
    problems = []
    # Catches a signing machine with a wrong clock.
    if not isinstance(catalog.get("time"), int) or catalog["time"] < MIN_TIME:
        problems.append("the catalog's time is before the App Store's floor " + str(MIN_TIME))
    # Against the catalog phones read now: an older one would be refused, and a package left out or a channel
    # set back by mistake stops its updates.
    if last is not None:
        problems += published_problems(catalog, last, set(allowed))
    for name, package in sorted(packages.items()):
        listed = inventory.get(name)
        if listed is None:
            problems.append(name + " is not a DiamaneOS package")
        elif package.get("source") != "DiamaneOS" or "originalPackage" in package:
            problems.append(name + ": not as the App Store takes DiamaneOS packages")
        elif sorted(package["signatures"]) != sorted(listed["signatures"]):
            problems.append(name + ": signers differ from the inventory")
        # The App Store parses each APK from the DiamaneOS catalog for its signer, and a split does not parse.
        elif any(v.get("apks") != ["base.apk"] for v in package.get("variants", {}).values()):
            problems.append(name + ": not a single APK")
        # A pinned maker's app is offered only on OS builds with its features, made for that version's APK.
        if name in PINNED:
            problems += filter(None, (pinned_version_problem(work, name, version, v)
                                      for version, v in sorted(package.get("variants", {}).items())))
        # Linked packages keep their group and dependencies, and no version names others.
        if name in LINKED and (package.get("group") != LINKED[name][0] or package.get("deps") != LINKED[name][1]
                               or "deps2" in package
                               or any(not isinstance(v, dict) or "deps" in v or "deps2" in v
                                      for v in package.get("variants", {}).values())):
            problems.append(name + ": not linked as LINKED says")
        # The inventory's label, when it has one, is the label of every version, and no field of the package.
        if "label" in package or (listed is not None and "label" in listed and any(
                not isinstance(v, dict) or v.get("label") != listed["label"] for v in package.get("variants", {}).values())):
            problems.append(name + ": a label that is not the inventory's, in every version and only there")
        # The App Store reads each version's label and refuses the whole catalog without one (RPackage in Repo.kt).
        if any(not isinstance(v, dict) or not isinstance(v.get("label"), str) or not v["label"].strip()
               for v in package.get("variants", {}).values()):
            problems.append(name + ": a version without a label")
        if listed is not None and (problem := icon_problem(work, name, package)):
            problems.append(problem)
    problems += [name + ": missing, but linked" for name in LINKED if name not in packages]
    for problem in problems:
        print(problem)
    if problems:
        sys.exit(1)
    print("the catalog lists only packages signed with the project's keys and its pinned makers' apps: " + ", ".join(sorted(packages)))


def main(args):
    if args[:1] == ["--check"]:
        first, allowed, paths, rest = "--first" in args, [], [], [a for a in args[1:] if a != "--first"]
        while rest:
            arg = rest.pop(0)
            if arg == "--allow-drop" and rest:
                allowed.append(rest.pop(0))
            else:
                paths.append(arg)
        # The published catalog is left out only with --first, which takes no --allow-drop.
        if len(paths) == (2 if first else 3) and not (first and allowed) \
                and not any(a.startswith("-") for a in paths + allowed):
            work, key, *published = map(os.path.abspath, paths)
            return check(work, key, published[0] if published else None, allowed)
    elif len(args) == 1 and not args[0].startswith("-"):
        return prepare(os.path.abspath(args[0]))
    sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
