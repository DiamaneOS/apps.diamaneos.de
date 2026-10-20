#!/usr/bin/env python3
"""Prepare and check the work tree of our catalog. It lists only our own builds.

./prepare.py WORK          copy the inventory, scripts and static files into WORK
./prepare.py --check WORK  after generate.py: the catalog lists exactly our packages, with their signers

The inventory is apps/packages/*/common-props.toml. GrapheneOS's apps are not in our catalog: the App
Store reads GrapheneOS's own catalog for them, mirrored by grapheneos-mirror.py, and refuses our
packages from it. The App Store also refuses any other package from our catalog (Catalogs.kt).
"""

import json
import os
import shutil
import sys
import tomllib

REPO = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = ["generate.py", "compress-apks", "process-static", "import-apks.py"]
# The packages the App Store takes from our catalog.
OURS = {"app.grapheneos.apps", "app.grapheneos.camera", "de.diamaneos.auditor"}


def load_inventory():
    packages_dir = os.path.join(REPO, "apps/packages")
    inventory = {}
    for name in sorted(os.listdir(packages_dir)):
        with open(os.path.join(packages_dir, name, "common-props.toml"), "rb") as f:
            inventory[name] = tomllib.load(f)
    problems = sorted(set(inventory) - OURS)
    problems += [name + " is not source DiamaneOS" for name, p in inventory.items() if p.get("source") != "DiamaneOS"]
    problems += [name + " has no signers" for name, p in inventory.items() if not p.get("signatures")]
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


def check(work):
    inventory = load_inventory()
    with open(os.path.join(work, "apps/metadata.1.json")) as f:
        packages = json.load(f)["packages"]
    problems = []
    for name, package in sorted(packages.items()):
        listed = inventory.get(name)
        if listed is None:
            problems.append(name + " is not ours")
        elif package.get("source") != "DiamaneOS" or "originalPackage" in package:
            problems.append(name + ": not as the App Store takes our packages")
        elif sorted(package["signatures"]) != sorted(listed["signatures"]):
            problems.append(name + ": signers differ from the inventory")
    for problem in problems:
        print(problem)
    if problems:
        sys.exit(1)
    print("our catalog lists only our packages: " + ", ".join(sorted(packages)))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        check(os.path.abspath(sys.argv[2]))
    elif len(sys.argv) == 2 and not sys.argv[1].startswith("-"):
        prepare(os.path.abspath(sys.argv[1]))
    else:
        sys.exit(__doc__)
