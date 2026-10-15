# Application repository boundaries

- Upstream provenance is in [UPSTREAM.json](UPSTREAM.json). The upstream MIT license is kept in [LICENSE](LICENSE).
- `mirror.py` and `grapheneos-apps.0.pub` are DiamaneOS additions. The key is GrapheneOS's catalog key, taken from its App Store source.
- Packages keep their own signing identities. Catalog authentication does not replace APK signature checks.
- The inventory turns off legacy fs-verity sidecars. Android 17 uses APK Signature Scheme v4 sidecars when supplied, alongside the APK's own signature and the catalog's hashes.
- Publication keeps the package versions that current and previous signed catalogs list. Serving roots hold verified files and signed metadata, never private keys.
- `deploy-static` calls the protected executable named by `DIAMANEOS_PUBLICATION_TRANSPORT`, which handles authentication, targets and remote installation.
- The Debian deployment entry point is [DiamaneOS/infrastructure](https://github.com/DiamaneOS/infrastructure/tree/main/debian).
