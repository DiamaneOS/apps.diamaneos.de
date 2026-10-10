# DiamaneOS application repository

Tools for generating signed application catalogs and publishing their package files. Unmodified applications retain their publisher signatures; repository metadata has a separate verification key.

`generate.py` produces the catalog using the package inventory and repository key. `deploy-static` publishes the generated tree to explicitly configured targets. Package versions referenced by signed catalogs remain available across tree switches.

Metadata uses the upstream signed-envelope format. APK signing certificates and APK signature scheme v4 remain independent of catalog authentication. Key generation and signing material are separate from the public serving tree.

Source provenance and deployment details are described in [DOWNSTREAM.md](DOWNSTREAM.md).
