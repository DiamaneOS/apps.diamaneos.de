# DiamaneOS app repository

apps.diamaneos.de serves two signed catalogs. The App Store checks each with its own key, and a package can come from only one of them.

- Our catalog (`metadata.1.0.sjson`), made with GrapheneOS's generator and signed with our offline catalog key. It lists only our App Store, Camera and Auditor (source `DiamaneOS`), signed with our app keys.
- GrapheneOS's catalog (`grapheneos/metadata.1.0.sjson`), served unchanged with its APKs. The App Store checks it with GrapheneOS's catalog key and takes only GrapheneOS's packages from it, without our packages, GrapheneOS's Info app (its release news) and GrapheneOS's Auditor.

## Building our catalog

The scripts need signify, apksigner and aapt2 from build tools 37 (generate.py reads apksigner's newer output), zopfli, brotli and GNU parallel.

1. `./prepare.py WORK` copies our inventory (`apps/packages`), the scripts and static files into a work tree.
2. In WORK, `./import-apks.py` adds our signed builds. Set each version's channel in its `channel.toml`.
3. In WORK, `./generate.py` writes the catalog and checks every APK's signer against the inventory. It signs with `apps.0.sec` when that key is in WORK.
4. `./prepare.py --check WORK apps.0.pub` checks the signed catalog with our catalog key's public key and confirms that it lists exactly our packages with their signers. Its time must be after the App Store's floor for our catalog (`minTimestamp` in Catalogs.kt).
5. `deploy-static` in WORK publishes the tree.

## GrapheneOS's catalog

`grapheneos-mirror.py ROOT STATE` runs on each server from `systemd/diamaneos-grapheneos-mirror.timer`, without any key. It fetches GrapheneOS's catalog and checks its signature (`grapheneos-apps.0.pub`) and that it is not older than the published one. It then fetches every APK the App Store may take from it for arm64-v8a and checks each against the catalog's sizes and SHA-256, and only then publishes the catalog bytes. Files that neither the current nor the previous catalog lists are removed.

Icons are not in the signed catalog. They are fetched again only with a new catalog, and a failed icon keeps the previous one. Packages GrapheneOS adds or drops, or signs with other keys, are logged and published anyway, as GrapheneOS's key is trusted for them. A failed run leaves the unit failed and the published catalog as it was.

Run the tests with `python3 -m unittest discover -s tests` (Python 3.11 or newer). One test compares the package sets with Catalogs.kt in an AppStore checkout next to this one, or at `APPSTORE_SOURCE`.

Source provenance and deployment: [DOWNSTREAM.md](DOWNSTREAM.md).
