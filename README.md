# DiamaneOS app repository

The catalog of apps.diamaneos.de, made with GrapheneOS's generator.

- Our App Store, Auditor and Camera (source `DiamaneOS` in the inventory) are our builds, signed with our app keys.
- Every other listed app is mirrored from GrapheneOS's repository and keeps its publisher's signature.
- Our catalog key signs the catalog. It is separate from the app keys, and the App Store trusts only this key.

## Building a catalog

The scripts need signify, apksigner and aapt2 from build tools 37 (generate.py reads apksigner's newer output), zopfli, brotli and GNU parallel.

1. `./mirror.py WORK` copies the inventory and scripts into a work tree and fetches GrapheneOS's catalog, checked with `grapheneos-apps.0.pub`. It downloads the listed apps for arm64-v8a and checks each file against the catalog's SHA-256 and sizes.
2. In WORK, `./import-apks.py` adds our builds. Set each version's channel in its `channel.toml`.
3. In WORK, `./generate.py` writes the catalog and checks every APK's signer against the inventory. It signs with `apps.0.sec` when that key is in WORK.
4. `./mirror.py --check WORK` confirms that the mirrored apps are listed exactly as GrapheneOS lists them.
5. `deploy-static` in WORK publishes the tree.

## Review

- A package GrapheneOS adds, or one whose signers or properties change, is held in `WORK/held.json`. It is listed only after its inventory entry is added or updated.
- New versions of listed packages are mirrored without review, in GrapheneOS's channels. Versions GrapheneOS drops stay as channel `old`.
- Versions come from GrapheneOS's signed catalog. The inherited version files under `apps/packages/*/<version>/` are not read.

Source provenance and deployment: [DOWNSTREAM.md](DOWNSTREAM.md).
