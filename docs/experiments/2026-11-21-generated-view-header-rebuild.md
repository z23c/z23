<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Generated view header rebuilds

A change to the explorer stylesheet on base `6ffef74044fd6599ce9af27239b61f9456ded761` regenerated the header in the first build. Its ten compiled consumers remained stale. A second invocation rebuilt all 3,027 node objects. With the correction, the first build updated the ten consumers and the source identity object. The following invocation rebuilt zero objects.

The generator stamp is a normal prerequisite of the header so GNU Make checks the output timestamp after the generator runs. Epoch object rules order compilation after header generation. The compiler depfile supplies ordinary dependencies for direct and transitive includes. An object whose imported prerequisites lack its source retains the conservative generated-header dependencies.

<!-- claim: symbol-present ZCL_UNTRACKED_VIEW_HEADERS Makefile # missing source edge retains generated-header dependencies -->

## Measurement

The experiment used GCC 14.2.0 on an AMD Ryzen 9 7950X3D, Linux x86-64, on 2026-11-21 UTC. Each series began with a verified warm `make -j8 build-only` and used the default compiler cache and LTO flags. Each row represents one successful invocation. CPU is user plus system time for Make and its descendants. Peak memory is the build cgroup high-water mark, including page cache. Hits and misses count only node-object lookups reported by zcc. The object count comes from publication timestamps under the object epoch.

| Tree | Input | Wall s | CPU s | Peak MiB | Cache hits | Cache misses | Objects |
|---|---|---:|---:|---:|---:|---:|---:|
| before | No edit | 4.45 | 4.83 | 57.9 | 0 | 0 | 0 |
| before | Isolated C edit | 5.30 | 5.37 | 60.3 | 0 | 2 | 2 |
| before | Shared header | 49.47 | 261.33 | 589.8 | 0 | 1523 | 1523 |
| before | CSS input | 4.82 | 5.21 | 58.5 | 0 | 1 | 1 |
| before | Following no-op | 163.19 | 607.58 | 790.1 | 0 | 3027 | 3027 |
| before | Makefile comment | 82.46 | 458.07 | 755.8 | 0 | 3027 | 3027 |
| after | No edit | 8.58 | 5.56 | 69.1 | 0 | 0 | 0 |
| after | Isolated C edit | 11.61 | 5.43 | 74.2 | 0 | 2 | 2 |
| after | Shared header | 56.83 | 262.58 | 542.7 | 0 | 1523 | 1523 |
| after | CSS input | 14.12 | 12.39 | 121.6 | 0 | 11 | 11 |
| after | Following no-op | 11.50 | 7.79 | 68.7 | 0 | 0 | 0 |
| after | Makefile comment | 144.23 | 549.02 | 773.4 | 0 | 3027 | 3027 |

Append a comment to `platform/modules/util/src/crc32c.c`, then to `platform/modules/base/include/base/log_macros.h`, running the build after each edit. Add a unique CSS declaration to `contexts/explorer/views/src/site.css`, build, and build again. Compare the published objects against the depfiles naming the generated header, plus `clientversion.o`. Materialize a consumer with GCC's `-r -flinker-output=nolto-rel` and check its bytes for the CSS declaration. The corrected name view contained the declaration after the first build.

For the Makefile case, append a comment to the root Makefile and run the same build. Its byte fingerprint selected a new epoch in both series. Shared-host load varied between invocations. Wall times are individual observations. The matched object sets and consumer bytes establish the change in required work.
