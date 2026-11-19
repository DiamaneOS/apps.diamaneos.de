# DiamaneOS app repository

apps.diamaneos.de serves two signed catalogs. The App Store checks each with its own key, and a package can come from only one of them.

- The DiamaneOS catalog (`metadata.1.0.sjson`), made with GrapheneOS's generator and signed with an offline catalog key. It lists only packages signed with the project's App Store, Camera or Auditor key (source `DiamaneOS`): the App Store, Camera, CameraProcessor and Auditor.
- GrapheneOS's catalog (`grapheneos/metadata.1.0.sjson`), served unchanged with its APKs. The App Store checks it with GrapheneOS's catalog key and takes only GrapheneOS's packages from it, without DiamaneOS packages, GrapheneOS's Info app (its release news) and GrapheneOS's Auditor.

Camera and CameraProcessor update together (`LINKED` in `prepare.py`): Camera names CameraProcessor as its dependency, so an update of Camera takes a newer CameraProcessor in the same install, and both share the group `camera`, one release channel.

The DiamaneOS catalog also offers other makers' apps that need a device's own parts, each pinned by name to its signer lineage in `prepare.py` (`PINNED`) and in the App Store's `Catalogs.kt` (`PINNED_PACKAGES`). Every version of such an app lists the system features it needs in its `props.toml`, and the App Store offers a version only on an OS build that declares them all. The only one is Fairphone's own camera app (`com.fps.camera`, signed by TCL). Its versions list `features = ["de.diamaneos.fairphone_camera"]`, which only Fairphone 6 builds with its camera algorithm service declare.

## Building the DiamaneOS catalog

The scripts need signify, apksigner and aapt2 from build tools 37 (generate.py reads apksigner's newer output), zopfli, brotli and GNU parallel.

1. `./prepare.py WORK` copies the inventory (`apps/packages`), the scripts and static files into a work tree.
2. In WORK, `./import-apks.py` adds the signed DiamaneOS builds. Set each version's channel in its `channel.toml`. A version's `props.toml` may set only `channel`, `features`, `requiredSystemFeatures` and `staticDeps`.
3. In WORK, `./generate.py` writes the catalog and checks every APK's signer against the inventory. It signs with `apps.0.sec` when that key is in WORK.
4. `./prepare.py --check WORK apps.0.pub PUBLISHED` checks the signed catalog with the catalog key's public key and confirms that the App Store can read it and that it lists only DiamaneOS packages with their signers, each as a single APK with a label in each version, and that each app on the main screen has a WebP icon of at most 1 MiB. It refuses a catalog whose time is before the App Store's floor for the DiamaneOS catalog (`minTimestamp` in Catalogs.kt), as from a signing machine with a wrong clock. PUBLISHED is the signed `metadata.1.0.sjson` as apps.diamaneos.de serves it, checked with the same key: the new catalog must be newer, keep each of its packages and offer a phone on each channel the same or a higher version code, picked as the App Store picks it, unless `--allow-drop PACKAGE[:CHANNEL]` names it. A first release has no published catalog and takes `--first` instead.
5. `deploy-static` in WORK publishes the tree.

## GrapheneOS's catalog

`grapheneos-mirror.py ROOT STATE` runs on each server from `systemd/diamaneos-grapheneos-mirror.timer`, without any key. It fetches GrapheneOS's catalog and checks its signature (`grapheneos-apps.0.pub`) and that it is not older than the published one or the newest one it ever published, which it keeps in STATE even when the served directory is emptied. It refuses a catalog that lists a path twice, a malformed entry, more than 20,000 files, a file over 512 MiB or more than 20 GiB in total. It then fetches every APK the App Store may take from it for arm64-v8a and checks each against the catalog's sizes and SHA-256, and only then publishes the catalog bytes. The files of a replaced catalog stay for 24 hours, and files that no kept catalog lists are removed. When GrapheneOS's catalog is more than 30 days old, the run does all this and then fails, so monitoring alerts.

Icons are not in the signed catalog. They are fetched again only with a new catalog or after a run that stopped before it moved a fetched icon in, and a failed icon keeps the previous one. Packages GrapheneOS adds or drops, or signs with other keys, are logged and published anyway, as GrapheneOS's key is trusted for them. A new icon replaces the published one only after the new catalog. A failed run leaves the unit failed and the published catalog and its icons as they were.

## Tests

Run the tests with `python3 -m unittest discover -s tests` (Python 3.11 or newer). One test compares the package sets with Catalogs.kt in an AppStore checkout next to this one, or at `APPSTORE_SOURCE`.

`tests/fuzz` holds Atheris fuzz targets with property checks for the mirror, the catalog check, generate.py and import-apks.py. The tests above do not use them. `tests/fuzz/regress.tar.gz` is a small merged corpus of every target. Replay it on the builder whenever the mirror, the catalog check, generate.py or import-apks.py changes.

The targets need Linux on x86_64 with Python 3.13, the only wheel `tests/fuzz/requirements.txt` allows, and OpenBSD signify. On Debian 13 without `python3-venv`, signify or root, as on the builder, set up a work folder once:

```sh
cd "$WORK"
apt-get download python3-pip-whl signify-openbsd
for deb in *.deb; do dpkg-deb -x "$deb" root; done
python3 -m venv --without-pip venv
pip=$(echo root/usr/share/python-wheels/pip-*.whl)
venv/bin/python "$pip/pip" install --require-hashes \
    -r "$APPS/tests/fuzz/requirements.txt"
```

Then replay from the checkout:

```sh
FUZZ_PYTHON="$WORK/venv/bin/python" FUZZ_SIGNIFY="$WORK/root/usr/bin/signify-openbsd" \
    nice -n 19 tests/fuzz/run.sh replay "$WORK/replay"
```

- The replay runs every input once. It fails when a target stops or records a kind of finding that `tests/fuzz/known-findings.txt` does not list. That list is empty, so any finding fails it.
- `run.sh TARGET SECONDS DIR` fuzzes one target, named by its file without `fuzz_`. The corpus, findings, log and throwaway test keys stay in DIR.
- `run.sh merge DIR` writes `DIR/regress.tar.gz` from the archive and the corpora in `DIR/<target>`, minimised. It takes only the public test key.

Source provenance and deployment: [DOWNSTREAM.md](DOWNSTREAM.md).
