# Application repository boundaries

Upstream provenance is recorded in [UPSTREAM.json](UPSTREAM.json). The upstream MIT license is retained in [LICENSE](LICENSE).

The upstream generator produces signed catalog metadata. Packages retain their own signing identities; catalog authentication does not replace APK signature verification. Package selection comes from the inventory used for generation.

The publisher invokes an externally configured transport after catalog generation. Publication preserves package versions referenced by current and previous signed catalogs. Serving roots contain verified artifacts and signed metadata, not release-signing private keys.

`deploy-static` calls the protected executable selected by `DIAMANEOS_PUBLICATION_TRANSPORT`. Authentication, target selection and remote installation belong to that transport.

The inherited package inventory describes upstream applications. DiamaneOS builds and their application identities require matching inventory entries. The Debian deployment entry point is [DiamaneOS/infrastructure](https://github.com/DiamaneOS/infrastructure/tree/main/debian).
