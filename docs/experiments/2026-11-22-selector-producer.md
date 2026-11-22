<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Selector producer setup

On 2026-11-22 UTC, four warm runs in the order shown compared `make -j8 dev-bin
ZCL_TEST_WERROR=1` with `make -j8 dev-proof-producer ZCL_TEST_WERROR=1` through
separate normal `devbuild --wait` admissions. The source commit was
`82bf0e32ab042f325bbcdf212aa20232f80d7ce9`; the selector compared it against
`7e05075d32a9c29040a80ad55f5f9d316deabdde`. The CPU was AMD Ryzen 9 7950X3D
and the compiler was GCC 14.2.0 (Ubuntu 14.2.0-4ubuntu2~24.04.1).

| Order | Target | Wall seconds | CPU seconds |
| --- | --- | ---: | ---: |
| 1 | `dev-bin` | 37.13 | 12.03 |
| 2 | `dev-proof-producer` | 11.20 | 9.60 |
| 3 | `dev-proof-producer` | 15.31 | 7.92 |
| 4 | `dev-bin` | 19.70 | 10.85 |

Each run passed. The selected exact set was the same 46 groups in all four
runs; the resulting `build/bin/z23-dev` SHA-256 was
`41990c348c8763ffba9159e1e7c4acb1cbf7ed5bfcf6bd2f2b87766582089038` in each.
Both `dev-bin` runs acquired the test-fast lease; neither producer run did.
These are two warm samples per target under host contention, not a stable
speedup estimate or an end-to-end verification benchmark. The exact test and
lint gates remain part of `agent-verify` after selection.
