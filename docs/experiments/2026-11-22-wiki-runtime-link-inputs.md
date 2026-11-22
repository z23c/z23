<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Standalone wiki qualifier link inputs

Linux GCC previously built all 3,027 common production-profile objects before
linking the wiki qualifier. The linker map on r1 showed that it extracted
23 archive members. The main and the trace constructor are explicit link
roots. The baseline x86-64-v3 build now requests the 23 members, trace and
main, using the existing production flags, object epochs and publication checks.
The archive takes its input order from the node source list. A dependency
change in the qualifier can require an update to the archive member list.

## Prebuild measurement

On 2026-11-22, r1 ran `devbuild --wait make -j8 proof-lint-prebuild` on a
Ryzen 9 7950X3D with GCC 14.2. Each row used a new production object epoch and
an empty private compiler cache. The baseline Makefile had one extra comment
to request a fresh epoch. Existing vendor archives were present in both jobs.

| Linux GCC prebuild, one run each | Wall s | CPU s | Node-profile objects compiled | Node-profile cache hits |
|---|---:|---:|---:|---:|
| Full archive prerequisites | 227.33 | 604.24 | 3,028 | 0 |
| Qualifier archive prerequisites | 56.97 | 80.57 | 25 | 0 |

All targets required by the lint prebuild completed. Elapsed times include
admission and competing host load. The prior committed-change verification
at `98035a9d97` also logged 3,028 node-object misses, with a 149 s prebuild.
These samples do not establish a fleet-wide speedup.

## Correctness controls

The measured full and reduced builds produced the same executable SHA-256,
`abcb27a63fc9e521b7c639e504be31e36aac6a2b1b6827a1dd2d717f9bd33073`.
Relinking both archive variants from the same retained objects reproduced
that digest. Omitting the fleet-board protocol object from the reduced
archive failed the link on the room validator and post verifier.

An isolated CLI fixture exercised two writers and two signed revisions per
writer. Both executables verified four revisions and twelve pairs. A changed
signature was refused with and without opt-in tracing. Usage, malformed and
empty plans produced the same refusals. The fixture did not contact live peers
or observe an OTLP mirror emission. GNU Make graph probes selected all 3,027
common inputs for Clang and for GCC with native architecture tuning. Those
probes check prerequisite selection only.
