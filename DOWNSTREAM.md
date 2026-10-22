# Application repository boundaries

- Upstream provenance is in [UPSTREAM.json](UPSTREAM.json). The upstream MIT license is kept in [LICENSE](LICENSE).
- `prepare.py`, `grapheneos-mirror.py`, `systemd/` and `grapheneos-apps.0.pub` are DiamaneOS additions. The key is GrapheneOS's catalog key, taken from its App Store source.
- `generate.py` also reads a label written in the manifest (aapt2 prints it only in its `application:` line), as the App Store needs a label in each version.
- `apps/packages` holds only our own packages. GrapheneOS's packages and their inherited version files were removed: they come from GrapheneOS's catalog.
- Packages keep their own signing identities. Catalog authentication does not replace APK signature checks.
- Our inventory turns off legacy fs-verity sidecars. Android 17 uses APK Signature Scheme v4 sidecars when supplied, alongside the APK's own signature and the catalog's hashes.
- Publication keeps the package versions that current and previous signed catalogs list. Serving roots hold verified files and signed metadata, never private keys.
- `deploy-static` calls the protected executable named by `DIAMANEOS_PUBLICATION_TRANSPORT`, which handles authentication, targets and remote installation.
- The Debian deployment entry point is [DiamaneOS/infrastructure](https://github.com/DiamaneOS/infrastructure/tree/main/debian).
- The GrapheneOS mirror runs as its own account (`diamaneos-apps-mirror`). It may write only its served directory and its state, and reaches only apps.grapheneos.org. Nginx serves the directory read-only as `/grapheneos/`.
