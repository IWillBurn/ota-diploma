# Licences

| What | Licence | File |
|---|---|---|
| Code of the bench: `bench/otabench/`, `bench/scripts/`, `bench/tests/`, `bench/clients/naive/`, `bench/clients/tuf-js/client.js`, `bench/updaters/`, `bench/vm/guest/` | Apache License 2.0 | [`LICENSE`](LICENSE) |
| Threat catalog and its schema (`bench/catalog/`), raw results (`bench/results/`), documentation and thesis drafts (`docs/`, `reports/`, `research_notes/`), figures (`docs/figures/`) | Creative Commons Attribution 4.0 International (CC BY 4.0) | <https://creativecommons.org/licenses/by/4.0/legalcode> |

Copyright 2026 IWillBurn (the otabench authors).

## Third-party files

* `bench/clients/python-tuf/python_tuf.py` comes from
  [tuf-conformance](https://github.com/theupdateframework/tuf-conformance)
  (`SPDX-License-Identifier: MIT OR Apache-2.0`, header kept in the file). The go-tuf
  client binary is built from the same project.
* `third_party/` holds clones of other projects (tuf-conformance, sparse clones for
  verification); they are not part of this repository's history and keep their own licences.
* Python and Node.js dependencies are installed by `bench/scripts/setup.ps1` /
  `bench/Dockerfile` and are not redistributed here.

The choice follows `docs/artifacts.md`: Apache-2.0 is compatible with tuf-conformance
(MIT OR Apache-2.0), CC BY 4.0 lets others reuse the catalog and the data with attribution.
